package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/mev-boost/config"
	"github.com/flashbots/mev-boost/server/types"
	"github.com/holiman/uint256"
	"github.com/sirupsen/logrus"
)

const (
	HeaderKeySlotUID      = "X-MEVBoost-SlotID"
	HeaderKeyVersion      = "X-MEVBoost-Version"
	HeaderStartTimeUnixMS = "X-MEVBoost-StartTimeUnixMS"
)

var (
	errHTTPErrorResponse  = errors.New("HTTP error response")
	errInvalidForkVersion = errors.New("invalid fork version")
	errMaxRetriesExceeded = errors.New("max retries exceeded")
)

// UserAgent is a custom string type to avoid confusing url + userAgent parameters in SendHTTPRequest
type UserAgent string

// BlockHashHex is a hex-string representation of a block hash
type BlockHashHex string

// SendHTTPRequest - prepare and send HTTP request, marshaling the payload if any, and decoding the response if dst is set
func SendHTTPRequest(ctx context.Context, client http.Client, method, url string, userAgent UserAgent, headers map[string]string, payload, dst any) (code int, err error) {
	var req *http.Request

	if payload == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return 0, fmt.Errorf("could not prepare request: %w", err)
		}
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		if err2 != nil {
			return 0, fmt.Errorf("could not marshal request: %w", err2)
		}
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payloadBytes))
		if err != nil {
			return 0, fmt.Errorf("could not prepare request: %w", err)
		}
		// Set Content-Type header
		req.Header.Add("Content-Type", "application/json")
	}

	// Set User-Agent header
	req.Header.Set("User-Agent", strings.TrimSpace(fmt.Sprintf("mev-boost/%s %s", config.Version, userAgent)))

	// Set other headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}

	if resp.StatusCode > 299 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read error response body for status code %d: %w", resp.StatusCode, err)
		}
		return resp.StatusCode, fmt.Errorf("%w: %d / %s", errHTTPErrorResponse, resp.StatusCode, string(bodyBytes))
	}

	if dst != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read response body: %w", err)
		}

		if err := json.Unmarshal(bodyBytes, dst); err != nil {
			return resp.StatusCode, fmt.Errorf("could not unmarshal response %s: %w", string(bodyBytes), err)
		}
	}

	return resp.StatusCode, nil
}

// SendHTTPRequestWithRetries - prepare and send HTTP request, retrying the request if within the client timeout
func SendHTTPRequestWithRetries(ctx context.Context, client http.Client, method, url string, userAgent UserAgent, headers map[string]string, payload, dst any, maxRetries int, log *logrus.Entry) (code int, err error) {
	var requestCtx context.Context
	var cancel context.CancelFunc
	if client.Timeout > 0 {
		// Create a context with a timeout as configured in the http client
		requestCtx, cancel = context.WithTimeout(context.Background(), client.Timeout)
	} else {
		requestCtx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	attempts := 0
	for {
		attempts++
		if requestCtx.Err() != nil {
			return 0, fmt.Errorf("request context error after %d attempts: %w", attempts, requestCtx.Err())
		}
		if attempts > maxRetries {
			return 0, errMaxRetriesExceeded
		}

		code, err = SendHTTPRequest(ctx, client, method, url, userAgent, headers, payload, dst)
		if err != nil {
			log.WithError(err).Warn("error making request to relay, retrying")
			time.Sleep(100 * time.Millisecond) // note: this timeout is only applied between retries, it does not delay the initial request!
			continue
		}
		return code, nil
	}
}

// ComputeDomain computes the signing domain
func ComputeDomain(domainType phase0.DomainType, forkVersionHex, genesisValidatorsRootHex string) (domain phase0.Domain, err error) {
	genesisValidatorsRoot := phase0.Root(common.HexToHash(genesisValidatorsRootHex))
	forkVersionBytes, err := hexutil.Decode(forkVersionHex)
	if err != nil || len(forkVersionBytes) != 4 {
		return domain, errInvalidForkVersion
	}
	var forkVersion [4]byte
	copy(forkVersion[:], forkVersionBytes[:4])
	return ssz.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot), nil
}

// DecodeJSON reads JSON from io.Reader and decodes it into a struct
func DecodeJSON(r io.Reader, dst any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

// bidResp are entries in the bids cache
type bidResp struct {
	t        time.Time
	response builderSpec.VersionedSignedBuilderBid
	bidInfo  bidInfo
	relays   []types.RelayEntry
}

// bidInfo is used to store bid response fields for logging and validation
type bidInfo struct {
	blockHash   phase0.Hash32
	parentHash  phase0.Hash32
	pubkey      phase0.BLSPubKey
	blockNumber uint64
	txRoot      phase0.Root
	value       *uint256.Int
}

func httpClientDisallowRedirects(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func weiBigIntToEthBigFloat(wei *big.Int) (ethValue *big.Float) {
	// wei / 10^18
	fbalance := new(big.Float)
	fbalance.SetString(wei.String())
	ethValue = new(big.Float).Quo(fbalance, big.NewFloat(1e18))
	return
}

func parseBidInfo(bid *builderSpec.VersionedSignedBuilderBid) (bidInfo, error) {
	blockHash, err := bid.BlockHash()
	if err != nil {
		return bidInfo{}, err
	}
	parentHash, err := bid.ParentHash()
	if err != nil {
		return bidInfo{}, err
	}
	pubkey, err := bid.Builder()
	if err != nil {
		return bidInfo{}, err
	}
	blockNumber, err := bid.BlockNumber()
	if err != nil {
		return bidInfo{}, err
	}
	txRoot, err := bid.TransactionsRoot()
	if err != nil {
		return bidInfo{}, err
	}
	value, err := bid.Value()
	if err != nil {
		return bidInfo{}, err
	}
	return bidInfo{
		blockHash:   blockHash,
		parentHash:  parentHash,
		pubkey:      pubkey,
		blockNumber: blockNumber,
		txRoot:      txRoot,
		value:       value,
	}, nil
}

func checkRelaySignature(bid *builderSpec.VersionedSignedBuilderBid, domain phase0.Domain, pubKey phase0.BLSPubKey) (bool, error) {
	root, err := bid.MessageHashTreeRoot()
	if err != nil {
		return false, err
	}
	sig, err := bid.Signature()
	if err != nil {
		return false, err
	}
	signingData := phase0.SigningData{ObjectRoot: root, Domain: domain}
	msg, err := signingData.HashTreeRoot()
	if err != nil {
		return false, err
	}

	return bls.VerifySignatureBytes(msg[:], sig[:], pubKey[:])
}

func getPayloadResponseIsEmpty(payload *builderApi.VersionedSubmitBlindedBlockResponse) bool {
	switch payload.Version {
	case spec.DataVersionBellatrix:
		if payload.Bellatrix == nil || payload.Bellatrix.BlockHash == nilHash {
			return true
		}
	case spec.DataVersionCapella:
		if payload.Capella == nil || payload.Capella.BlockHash == nilHash {
			return true
		}
	case spec.DataVersionDeneb:
		if payload.Deneb == nil || payload.Deneb.ExecutionPayload == nil ||
			payload.Deneb.ExecutionPayload.BlockHash == nilHash ||
			payload.Deneb.BlobsBundle == nil {
			return true
		}
	case spec.DataVersionElectra:
		if payload.Electra == nil || payload.Electra.ExecutionPayload == nil ||
			payload.Electra.ExecutionPayload.BlockHash == nilHash ||
			payload.Electra.BlobsBundle == nil {
			return true
		}
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair:
		return true
	}
	return false
}

func wrapUserAgent(ua UserAgent) string {
	return strings.TrimSpace(fmt.Sprintf("mev-boost/%s %s", config.Version, ua))
}
