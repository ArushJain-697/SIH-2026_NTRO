// Package ipsec tracks ESP and AH Security Association inventories from
// captured datagrams, including directional pairing, rekey detection,
// and sequence analysis indicators.
package ipsec

import (
	"fmt"
	"math"
	"net"
	"time"
)

// Protocol identifies ESP or AH.
type Protocol uint8

const (
	ProtoESP Protocol = 50
	ProtoAH  Protocol = 51
)

// DirectionalSA tracks one direction of an ESP or AH SA.
type DirectionalSA struct {
	// Key fields: destination + SPI + protocol
	DstIP    net.IP
	SPI      uint32
	Protocol Protocol
	SrcIP    net.IP

	// Counters
	Packets uint64
	Bytes   uint64

	// Timing
	FirstTime time.Time
	LastTime  time.Time
	FirstPkt  int
	LastPkt   int

	// Sequence analysis
	MinSeq      uint32
	MaxSeq      uint32
	Gaps        uint64 // out-of-order or missing
	Duplicates  uint64
	Regressions uint64 // seq < previous

	// Size summary
	MinSize uint32
	MaxSize uint32
	SizeSum uint64

	lastSeq uint32
}

// SAPair is a bidirectional SA pair.
type SAPair struct {
	Outbound  *DirectionalSA
	Inbound   *DirectionalSA
	FirstTime time.Time
	LastTime  time.Time
}

// Inventory tracks all observed ESP/AH SAs.
type Inventory struct {
	SAs   map[string]*DirectionalSA // key: dst|spi|proto
	Pairs []*SAPair
}

// NewInventory creates an empty SA inventory.
func NewInventory() *Inventory {
	return &Inventory{
		SAs: make(map[string]*DirectionalSA),
	}
}

func saKey(dst net.IP, spi uint32, proto Protocol) string {
	return fmt.Sprintf("%s|%08x|%d", dst.String(), spi, proto)
}

// AddPacket records an ESP or AH packet.
func (inv *Inventory) AddPacket(srcIP, dstIP net.IP, spi uint32, seq uint32, proto Protocol, size uint32, ts time.Time, pktIdx int) {
	key := saKey(dstIP, spi, proto)
	sa, exists := inv.SAs[key]
	if !exists {
		sa = &DirectionalSA{
			DstIP:     dstIP,
			SPI:       spi,
			Protocol:  proto,
			SrcIP:     srcIP,
			FirstTime: ts,
			FirstPkt:  pktIdx,
			MinSeq:    seq,
			MaxSeq:    seq,
			MinSize:   size,
			MaxSize:   size,
			lastSeq:   seq,
		}
		inv.SAs[key] = sa
	}

	sa.Packets++
	sa.Bytes += uint64(size)
	sa.LastTime = ts
	sa.LastPkt = pktIdx

	// Sequence analysis.
	if sa.Packets > 1 {
		if seq == sa.lastSeq {
			sa.Duplicates++
		} else if seq < sa.lastSeq {
			sa.Regressions++
		} else if seq > sa.lastSeq+1 {
			sa.Gaps++
		}
	}
	if seq < sa.MinSeq {
		sa.MinSeq = seq
	}
	if seq > sa.MaxSeq {
		sa.MaxSeq = seq
	}
	sa.lastSeq = seq

	// Size tracking.
	if size < sa.MinSize {
		sa.MinSize = size
	}
	if size > sa.MaxSize {
		sa.MaxSize = size
	}
	sa.SizeSum += uint64(size)
}

// BuildPairs pairs SAs by reversed endpoints.
func (inv *Inventory) BuildPairs() {
	paired := make(map[string]bool)

	for key, sa := range inv.SAs {
		if paired[key] {
			continue
		}

		// Find the reverse direction.
		for key2, sa2 := range inv.SAs {
			if key2 == key || paired[key2] {
				continue
			}
			if sa2.SrcIP.Equal(sa.DstIP) && sa2.DstIP.Equal(sa.SrcIP) && sa2.Protocol == sa.Protocol {
				// Check timing (within 5 seconds).
				timeDiff := math.Abs(sa.FirstTime.Sub(sa2.FirstTime).Seconds())
				if timeDiff <= 5.0 {
					pair := &SAPair{
						Outbound:  sa,
						Inbound:   sa2,
						FirstTime: sa.FirstTime,
						LastTime:  sa.LastTime,
					}
					if sa2.FirstTime.Before(pair.FirstTime) {
						pair.FirstTime = sa2.FirstTime
					}
					if sa2.LastTime.After(pair.LastTime) {
						pair.LastTime = sa2.LastTime
					}
					inv.Pairs = append(inv.Pairs, pair)
					paired[key] = true
					paired[key2] = true
					break
				}
			}
		}
	}
}

// GapRatio returns the ratio of gaps to total packets for a directional SA.
func (sa *DirectionalSA) GapRatio() float64 {
	if sa.Packets <= 1 {
		return 0
	}
	return float64(sa.Gaps) / float64(sa.Packets-1)
}

// MeanSize returns the mean packet size.
func (sa *DirectionalSA) MeanSize() float64 {
	if sa.Packets == 0 {
		return 0
	}
	return float64(sa.SizeSum) / float64(sa.Packets)
}
