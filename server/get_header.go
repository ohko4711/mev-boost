package server

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/mev-boost/config"
	"github.com/flashbots/mev-boost/server/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// getHeader requests a bid from each relay and returns the most profitable one
func (m *BoostService) getHeader(log *logrus.Entry, ua UserAgent, slot phase0.Slot, pubkey, parentHashHex string) (bidResp, error) {
	// Ensure arguments are valid
	if len(pubkey) != 98 {
		return bidResp{}, errInvalidPubkey
	}
	if len(parentHashHex) != 66 {
		return bidResp{}, errInvalidHash
	}

	// Make sure we have a uid for this slot
	m.slotUIDLock.Lock()
	if m.slotUID.slot < slot {
		m.slotUID.slot = slot
		m.slotUID.uid = uuid.New()
	}
	slotUID := m.slotUID.uid
	m.slotUIDLock.Unlock()
	log = log.WithField("slotUID", slotUID)

	// Log how late into the slot the request starts
	slotStartTimestamp := m.genesisTime + uint64(slot)*config.SlotTimeSec
	msIntoSlot := uint64(time.Now().UTC().UnixMilli()) - slotStartTimestamp*1000
	log.WithFields(logrus.Fields{
		"genesisTime": m.genesisTime,
		"slotTimeSec": config.SlotTimeSec,
		"msIntoSlot":  msIntoSlot,
	}).Infof("getHeader request start - %d milliseconds into slot %d", msIntoSlot, slot)

	// Add request headers
	headers := map[string]string{
		HeaderKeySlotUID:      slotUID.String(),
		HeaderStartTimeUnixMS: fmt.Sprintf("%d", time.Now().UTC().UnixMilli()),
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup

		// The final response, containing the highest bid (if any)
		result = bidResp{}

		// Relays that sent the bid for a specific blockHash
		relays = make(map[BlockHashHex][]types.RelayEntry)
	)

	// Request a bid from each relay
	for _, relay := range m.relays {
		wg.Add(1)
		go func(relay types.RelayEntry) {
			defer wg.Done()

			// Build the request URL
			url := relay.GetURI(fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", slot, parentHashHex, pubkey))
			log := log.WithField("url", url)

			// Send the get bid request to the relay
			bid := new(builderSpec.VersionedSignedBuilderBid)
			code, err := SendHTTPRequest(context.Background(), m.httpClientGetHeader, http.MethodGet, url, ua, headers, nil, bid)
			if err != nil {
				log.WithError(err).Warn("error making request to relay")
				return
			}
			if code == http.StatusNoContent {
				log.Debug("no-content response")
				return
			}

			// Skip if bid is empty
			if bid.IsEmpty() {
				return
			}

			// Getting the bid info will check if there are missing fields in the response
			bidInfo, err := parseBidInfo(bid)
			if err != nil {
				log.WithError(err).Warn("error parsing bid info")
				return
			}

			// Ignore bids with an empty block
			if bidInfo.blockHash == nilHash {
				log.Warn("relay responded with empty block hash")
				return
			}

			// Add some info about the bid to the logger
			valueEth := weiBigIntToEthBigFloat(bidInfo.value.ToBig())
			log = log.WithFields(logrus.Fields{
				"blockNumber": bidInfo.blockNumber,
				"blockHash":   bidInfo.blockHash.String(),
				"txRoot":      bidInfo.txRoot.String(),
				"value":       valueEth.Text('f', 18),
			})

			// Ensure the bid uses the correct public key
			if relay.PublicKey.String() != bidInfo.pubkey.String() {
				log.Errorf("bid pubkey mismatch. expected: %s - got: %s", relay.PublicKey.String(), bidInfo.pubkey.String())
				return
			}

			// Verify the relay signature in the relay response
			if !config.SkipRelaySignatureCheck {
				ok, err := checkRelaySignature(bid, m.builderSigningDomain, relay.PublicKey)
				if err != nil {
					log.WithError(err).Error("error verifying relay signature")
					return
				}
				if !ok {
					log.Error("failed to verify relay signature")
					return
				}
			}

			// Verify response coherence with proposer's input data
			if bidInfo.parentHash.String() != parentHashHex {
				log.WithFields(logrus.Fields{
					"originalParentHash": parentHashHex,
					"responseParentHash": bidInfo.parentHash.String(),
				}).Error("proposer and relay parent hashes are not the same")
				return
			}

			// Ignore bids with 0 value
			isZeroValue := bidInfo.value.IsZero()
			isEmptyListTxRoot := bidInfo.txRoot.String() == "0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1"
			if isZeroValue || isEmptyListTxRoot {
				log.Warn("ignoring bid with 0 value")
				return
			}

			log.Debug("bid received")

			// Skip if value is lower than the minimum bid
			if bidInfo.value.CmpBig(m.relayMinBid.BigInt()) == -1 {
				log.Debug("ignoring bid below min-bid value")
				return
			}

			mu.Lock()
			defer mu.Unlock()

			// Remember which relays delivered which bids (multiple relays might deliver the top bid)
			relays[BlockHashHex(bidInfo.blockHash.String())] = append(relays[BlockHashHex(bidInfo.blockHash.String())], relay)

			// Compare the bid with already known top bid (if any)
			if !result.response.IsEmpty() {
				valueDiff := bidInfo.value.Cmp(result.bidInfo.value)
				if valueDiff == -1 {
					// The current bid is less profitable than already known one
					return
				} else if valueDiff == 0 {
					// The current bid is equally profitable as already known one
					// Use hash as tiebreaker
					previousBidBlockHash := result.bidInfo.blockHash
					if bidInfo.blockHash.String() >= previousBidBlockHash.String() {
						return
					}
				}
			}

			// Use this relay's response as mev-boost response because it's most profitable
			log.Debug("new best bid")
			result.response = *bid
			result.bidInfo = bidInfo
			result.t = time.Now()
		}(relay)
	}
	wg.Wait()

	// Set the winning relays before returning
	result.relays = relays[BlockHashHex(result.bidInfo.blockHash.String())]
	return result, nil
}
