// Package engine wires the full analysis pipeline: decode → IKE → SA inventory
// → evidence → assessment → result. All state lives in the call.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/SIH-2026/trace/internal/assess"
	"github.com/SIH-2026/trace/internal/evidence"
	"github.com/SIH-2026/trace/internal/iana"
	"github.com/SIH-2026/trace/internal/ike"
	"github.com/SIH-2026/trace/internal/ipsec"
	"github.com/SIH-2026/trace/internal/netdec"
	"github.com/SIH-2026/trace/internal/pcap"
	"github.com/SIH-2026/trace/internal/policy"
)

// State represents the analysis state.
type State string

const (
	StateCompleted      State = "COMPLETED"
	StateCompletedNoIPs State = "COMPLETED_NO_IPSEC"
	StateFailed         State = "FAILED"
)

// Options configures the analysis.
type Options struct {
	Profile     string
	GatewayFile string
}

// InputSummary describes the input capture.
type InputSummary struct {
	Format    string            `json:"format"`
	Size      int64             `json:"size"`
	SHA256    string            `json:"sha256"`
	LinkTypes map[string]uint64 `json:"link_types"`
	Stats     netdec.Stats      `json:"stats"`
}

// Result is the trace.result.v1 output.
type Result struct {
	Schema     string              `json:"schema"`
	Version    string              `json:"version"`
	State      State               `json:"state"`
	Input      InputSummary        `json:"input"`
	IKESAs     []*ike.SA           `json:"ike_sas"`
	ChildSAs   int                 `json:"child_sa_pairs"`
	Evidence   []evidence.Evidence `json:"evidence"`
	Assessment *assess.Assessment  `json:"assessment"`
	PolicyID   string              `json:"policy_id"`
	ModelID    string              `json:"model_id,omitempty"`
	Generated  time.Time           `json:"generated"`
	Error      string              `json:"error,omitempty"`
}

// Analyze runs the full analysis pipeline.
func Analyze(r io.Reader, size int64, opts Options) (*Result, error) {
	result := &Result{
		Schema:    "trace.result.v1",
		Version:   "1.0.0",
		Generated: time.Now(),
		PolicyID:  policy.PolicyVersion,
	}

	// Compute SHA-256 while reading.
	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)

	// Open the capture.
	reader, err := pcap.Open(tee)
	if err != nil {
		result.State = StateFailed
		result.Error = fmt.Sprintf("Failed to open capture: %v", err)
		return result, nil
	}

	result.Input.Format = reader.Format().String()
	result.Input.Size = size

	// Create the decoder.
	decoder := netdec.NewDecoder(reader)

	// IKE SA table.
	saTable := ike.NewSATable()

	// ESP/AH inventory.
	espInv := ipsec.NewInventory()

	// Evidence ledger.
	ledger := evidence.NewLedger()

	// Process all packets.
	for {
		dg, err := decoder.Next()
		if err != nil {
			break
		}

		switch dg.Kind {
		case netdec.KindIKE:
			msg, err := ike.ParseMessage(dg.Payload)
			if err != nil || msg == nil {
				continue
			}
			saTable.Process(msg, dg.SrcIP, dg.DstIP, dg.SrcPort, dg.DstPort, dg.PacketIndex, dg.Timestamp)

		case netdec.KindESP:
			espInv.AddPacket(dg.SrcIP, dg.DstIP, dg.SPI, dg.Sequence, ipsec.ProtoESP, uint32(len(dg.Payload)), dg.Timestamp, dg.PacketIndex)

		case netdec.KindAH:
			espInv.AddPacket(dg.SrcIP, dg.DstIP, dg.SPI, dg.Sequence, ipsec.ProtoAH, uint32(len(dg.Payload)), dg.Timestamp, dg.PacketIndex)
		}
	}

	// Finalize.
	result.Input.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	stats := decoder.Stats()
	result.Input.Stats = stats

	// Convert link types.
	result.Input.LinkTypes = make(map[string]uint64)
	for lt, count := range stats.LinkTypes {
		result.Input.LinkTypes[fmt.Sprintf("%d", lt)] = count
	}

	// Pair ESP/AH SAs.
	espInv.BuildPairs()
	result.ChildSAs = len(espInv.Pairs)

	// Collect IKE SAs.
	for _, sa := range saTable.SAs {
		result.IKESAs = append(result.IKESAs, sa)
	}

	// Determine state.
	if stats.IPsec == 0 {
		result.State = StateCompletedNoIPs
	} else {
		result.State = StateCompleted
	}

	// Get profile.
	prof := policy.GetProfile(opts.Profile)

	// Run assessment.
	result.Assessment = assess.Assess(saTable, espInv, ledger, prof)

	// Store evidence.
	result.Evidence = ledger.All()

	return result, nil
}

// Version information.
var (
	BuildVersion = "dev"
	IANAVersion  = iana.RegistryVersion
)
