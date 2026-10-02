// Package netdec decodes link-layer, IP and IPsec protocol headers from
// captured packets. It classifies datagrams as IKE, ESP, AH or NAT-T
// keepalive and provides complete skip accounting.
package netdec

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/SIH-2026/trace/internal/pcap"
)

// DatagramKind classifies the IPsec-relevant type of a datagram.
type DatagramKind int

const (
	KindIKE          DatagramKind = iota // UDP 500 or NAT-T non-ESP marker
	KindESP                              // Protocol 50 or ESP-in-UDP (port 4500)
	KindAH                               // Protocol 51
	KindNATKeepalive                     // Single 0xFF byte on UDP 4500
	KindNonIPsec                         // Other traffic
)

func (k DatagramKind) String() string {
	switch k {
	case KindIKE:
		return "IKE"
	case KindESP:
		return "ESP"
	case KindAH:
		return "AH"
	case KindNATKeepalive:
		return "NAT-Keepalive"
	case KindNonIPsec:
		return "non-IPsec"
	default:
		return fmt.Sprintf("Kind(%d)", k)
	}
}

// Datagram is a decoded IP datagram classified for IPsec analysis.
type Datagram struct {
	// PacketIndex is the 0-based packet number from the capture file.
	PacketIndex int
	// Timestamp of capture.
	Timestamp time.Time
	// SrcIP and DstIP are the IP endpoints.
	SrcIP net.IP
	DstIP net.IP
	// SrcPort and DstPort for UDP; 0 for raw ESP/AH.
	SrcPort uint16
	DstPort uint16
	// IPVersion is 4 or 6.
	IPVersion int
	// Kind classifies the IPsec relevance.
	Kind DatagramKind
	// Payload is the protocol payload (IKE message, ESP header+data, etc.).
	Payload []byte
	// SPI for ESP/AH (first 4 bytes of protocol header); 0 for IKE.
	SPI uint32
	// Sequence number for ESP/AH.
	Sequence uint32
	// AHICVLen is the ICV length in bytes for AH, derived from the payload length field.
	AHICVLen int
	// Truncated is true if the original packet was larger than captured.
	Truncated bool
}

// UnsupportedLinkType is returned when a link-layer type is not supported.
type UnsupportedLinkType struct {
	Type pcap.LinkType
}

func (e UnsupportedLinkType) Error() string {
	return fmt.Sprintf("netdec: unsupported link type %d", e.Type)
}

// SkipReason categorises why a packet was skipped.
type SkipReason string

const (
	SkipUnsupportedLink SkipReason = "unsupported_linktype"
	SkipNotIP           SkipReason = "not_ip"
	SkipTruncated       SkipReason = "truncated"
	SkipFragmentPending SkipReason = "fragment_pending"
	SkipMalformed       SkipReason = "malformed"
	SkipNonIPsec        SkipReason = "non_ipsec"
)

// Stats tracks decode statistics.
type Stats struct {
	Seen      uint64
	Decoded   uint64
	IPsec     uint64
	Skipped   map[SkipReason]uint64
	LinkTypes map[pcap.LinkType]uint64
	Warnings  []string
}

func newStats() *Stats {
	return &Stats{
		Skipped:   make(map[SkipReason]uint64),
		LinkTypes: make(map[pcap.LinkType]uint64),
	}
}

// DecodeLink extracts the IP payload from a link-layer frame.
// Returns the payload, the EtherType (0x0800 IPv4, 0x86DD IPv6), and error.
func DecodeLink(data []byte, lt pcap.LinkType) ([]byte, uint16, error) {
	switch lt {
	case pcap.LinkEthernet:
		return decodeLinkEthernet(data)
	case pcap.LinkLinuxSLL:
		return decodeLinkSLL(data)
	case pcap.LinkLinuxSLL2:
		return decodeLinkSLL2(data)
	case pcap.LinkNull, pcap.LinkBSDLoop:
		return decodeLinkNull(data)
	case pcap.LinkRawIP, pcap.LinkRawIPv4, pcap.LinkRawIPv6,
		pcap.LinkRawIPv4DLT, pcap.LinkRawIPv6DLT:
		return decodeLinkRawIP(data, lt)
	default:
		return nil, 0, UnsupportedLinkType{Type: lt}
	}
}

func decodeLinkEthernet(data []byte) ([]byte, uint16, error) {
	if len(data) < 14 {
		return nil, 0, fmt.Errorf("netdec: ethernet frame too short (%d bytes)", len(data))
	}
	etherType := binary.BigEndian.Uint16(data[12:14])
	payload := data[14:]

	// Handle VLAN tags: 802.1Q (0x8100) and 802.1ad (0x88A8, 0x9100).
	for etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100 {
		if len(payload) < 4 {
			return nil, 0, fmt.Errorf("netdec: VLAN tag truncated")
		}
		etherType = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}

	return payload, etherType, nil
}

func decodeLinkSLL(data []byte) ([]byte, uint16, error) {
	// Linux SLL: 16-byte header.
	if len(data) < 16 {
		return nil, 0, fmt.Errorf("netdec: SLL frame too short (%d bytes)", len(data))
	}
	etherType := binary.BigEndian.Uint16(data[14:16])
	return data[16:], etherType, nil
}

func decodeLinkSLL2(data []byte) ([]byte, uint16, error) {
	// Linux SLL2: 20-byte header.
	if len(data) < 20 {
		return nil, 0, fmt.Errorf("netdec: SLL2 frame too short (%d bytes)", len(data))
	}
	etherType := binary.BigEndian.Uint16(data[0:2])
	return data[20:], etherType, nil
}

func decodeLinkNull(data []byte) ([]byte, uint16, error) {
	// BSD null/loopback: 4-byte header with address family.
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("netdec: null frame too short (%d bytes)", len(data))
	}
	payload := data[4:]

	// The 4-byte header contains a host-endian address family.
	// But we can also just look at the IP version nibble in the payload.
	if len(payload) == 0 {
		return nil, 0, fmt.Errorf("netdec: null frame empty after header")
	}

	version := payload[0] >> 4
	switch version {
	case 4:
		return payload, 0x0800, nil
	case 6:
		return payload, 0x86DD, nil
	default:
		// Fall back to the address family.
		af := binary.LittleEndian.Uint32(data[0:4])
		switch af {
		case 2: // AF_INET
			return payload, 0x0800, nil
		case 24, 28, 30: // AF_INET6 on different BSDs
			return payload, 0x86DD, nil
		default:
			return nil, 0, fmt.Errorf("netdec: null/loopback: unknown AF %d, IP version %d", af, version)
		}
	}
}

func decodeLinkRawIP(data []byte, lt pcap.LinkType) ([]byte, uint16, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("netdec: raw IP frame empty")
	}

	switch lt {
	case pcap.LinkRawIPv4, pcap.LinkRawIPv4DLT:
		return data, 0x0800, nil
	case pcap.LinkRawIPv6, pcap.LinkRawIPv6DLT:
		return data, 0x86DD, nil
	default:
		// LinkRawIP (101): detect from version nibble.
		version := data[0] >> 4
		switch version {
		case 4:
			return data, 0x0800, nil
		case 6:
			return data, 0x86DD, nil
		default:
			return nil, 0, fmt.Errorf("netdec: raw IP: unknown version %d", version)
		}
	}
}

// IPResult holds the result of IP header decoding.
type IPResult struct {
	SrcIP     net.IP
	DstIP     net.IP
	Protocol  uint8
	Payload   []byte
	Version   int
	Truncated bool
	// Fragment fields (zero if not a fragment).
	FragID     uint32
	FragOffset uint16
	FragMore   bool
}

// DecodeIPv4 decodes an IPv4 header and returns the transport payload.
func DecodeIPv4(data []byte) (*IPResult, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("netdec: IPv4 header too short (%d bytes)", len(data))
	}

	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || ihl > len(data) {
		return nil, fmt.Errorf("netdec: IPv4 IHL invalid (%d)", ihl)
	}

	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	protocol := data[9]
	srcIP := net.IP(make([]byte, 4))
	copy(srcIP, data[12:16])
	dstIP := net.IP(make([]byte, 4))
	copy(dstIP, data[16:20])

	// Fragment fields.
	flagsOffset := binary.BigEndian.Uint16(data[6:8])
	fragMore := (flagsOffset & 0x2000) != 0
	fragOffset := (flagsOffset & 0x1FFF) * 8
	fragID := uint32(binary.BigEndian.Uint16(data[4:6]))

	truncated := false
	var payload []byte
	if totalLen <= ihl {
		payload = nil
	} else if totalLen > len(data) {
		// Snaplen truncation — flag it, keep what we have.
		truncated = true
		if ihl < len(data) {
			payload = data[ihl:]
		}
	} else {
		payload = data[ihl:totalLen]
	}

	return &IPResult{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Protocol:   protocol,
		Payload:    payload,
		Version:    4,
		Truncated:  truncated,
		FragID:     fragID,
		FragOffset: fragOffset,
		FragMore:   fragMore,
	}, nil
}

// DecodeIPv6 decodes an IPv6 header, skipping known extension headers.
func DecodeIPv6(data []byte) (*IPResult, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("netdec: IPv6 header too short (%d bytes)", len(data))
	}

	payloadLen := int(binary.BigEndian.Uint16(data[4:6]))
	nextHeader := data[6]
	srcIP := net.IP(make([]byte, 16))
	copy(srcIP, data[8:24])
	dstIP := net.IP(make([]byte, 16))
	copy(dstIP, data[24:40])

	truncated := false
	payload := data[40:]
	if payloadLen > len(payload) {
		truncated = true
	} else {
		payload = payload[:payloadLen]
	}

	result := &IPResult{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Version:   6,
		Truncated: truncated,
	}

	// Walk extension headers.
	for {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-hop, routing, destination
			if len(payload) < 2 {
				return nil, fmt.Errorf("netdec: IPv6 ext header truncated")
			}
			extLen := int(payload[1]+1) * 8
			if extLen > len(payload) {
				return nil, fmt.Errorf("netdec: IPv6 ext header length exceeds payload")
			}
			nextHeader = payload[0]
			payload = payload[extLen:]

		case 44: // Fragment header
			if len(payload) < 8 {
				return nil, fmt.Errorf("netdec: IPv6 fragment header truncated")
			}
			nextHeader = payload[0]
			fragOffsetFlags := binary.BigEndian.Uint16(payload[2:4])
			result.FragOffset = (fragOffsetFlags >> 3) * 8
			result.FragMore = (fragOffsetFlags & 0x01) != 0
			result.FragID = binary.BigEndian.Uint32(payload[4:8])
			payload = payload[8:]

		default:
			// This is the transport protocol.
			result.Protocol = nextHeader
			result.Payload = payload
			return result, nil
		}
	}
}

// ClassifyIPsec classifies the IP payload as an IPsec datagram.
func ClassifyIPsec(ip *IPResult, srcPort, dstPort uint16, payload []byte) (DatagramKind, uint32, uint32, int) {
	switch ip.Protocol {
	case 50: // ESP
		if len(payload) < 8 {
			return KindNonIPsec, 0, 0, 0
		}
		spi := binary.BigEndian.Uint32(payload[0:4])
		seq := binary.BigEndian.Uint32(payload[4:8])
		return KindESP, spi, seq, 0

	case 51: // AH
		if len(payload) < 12 {
			return KindNonIPsec, 0, 0, 0
		}
		// AH header: next(1), payloadLen(1), reserved(2), SPI(4), seq(4)
		ahPayloadLen := int(payload[1])
		icvLen := (ahPayloadLen - 1) * 4 // ICV length in bytes
		if icvLen < 0 {
			icvLen = 0
		}
		spi := binary.BigEndian.Uint32(payload[4:8])
		seq := binary.BigEndian.Uint32(payload[8:12])
		return KindAH, spi, seq, icvLen

	case 17: // UDP
		if len(payload) < 8 {
			return KindNonIPsec, 0, 0, 0
		}
		sport := binary.BigEndian.Uint16(payload[0:2])
		dport := binary.BigEndian.Uint16(payload[2:4])
		udpLen := binary.BigEndian.Uint16(payload[4:6])
		_ = udpLen

		udpPayload := payload[8:]

		if sport == 500 || dport == 500 {
			return KindIKE, 0, 0, 0
		}

		if sport == 4500 || dport == 4500 {
			if len(udpPayload) == 0 {
				return KindNonIPsec, 0, 0, 0
			}
			// Single 0xFF byte = NAT keepalive.
			if len(udpPayload) == 1 && udpPayload[0] == 0xFF {
				return KindNATKeepalive, 0, 0, 0
			}
			// Four zero bytes = non-ESP marker → IKE.
			if len(udpPayload) >= 4 {
				marker := binary.BigEndian.Uint32(udpPayload[0:4])
				if marker == 0 {
					return KindIKE, 0, 0, 0
				}
				// Non-zero SPI → ESP-in-UDP.
				spi := marker
				if len(udpPayload) >= 8 {
					seq := binary.BigEndian.Uint32(udpPayload[4:8])
					return KindESP, spi, seq, 0
				}
				return KindESP, spi, 0, 0
			}
			return KindNonIPsec, 0, 0, 0
		}

		return KindNonIPsec, 0, 0, 0

	default:
		return KindNonIPsec, 0, 0, 0
	}
}

// DecodePacket takes a raw packet with its link type and returns a classified Datagram.
// Returns nil, reason if the packet should be skipped.
func DecodePacket(pkt pcap.Packet) (*Datagram, SkipReason) {
	// Decode link layer.
	ipData, etherType, err := DecodeLink(pkt.Data, pkt.LinkType)
	if err != nil {
		if _, ok := err.(UnsupportedLinkType); ok {
			return nil, SkipUnsupportedLink
		}
		return nil, SkipMalformed
	}

	// Decode IP.
	var ip *IPResult
	switch etherType {
	case 0x0800:
		ip, err = DecodeIPv4(ipData)
	case 0x86DD:
		ip, err = DecodeIPv6(ipData)
	default:
		return nil, SkipNotIP
	}
	if err != nil {
		return nil, SkipMalformed
	}

	// Check for fragments.
	if ip.FragOffset != 0 || ip.FragMore {
		// Fragment — would need reassembly.
		return nil, SkipFragmentPending
	}

	// Extract ports and classify.
	var srcPort, dstPort uint16
	if ip.Protocol == 17 && len(ip.Payload) >= 8 { // UDP
		srcPort = binary.BigEndian.Uint16(ip.Payload[0:2])
		dstPort = binary.BigEndian.Uint16(ip.Payload[2:4])
	}

	kind, spi, seq, ahICVLen := ClassifyIPsec(ip, srcPort, dstPort, ip.Payload)
	if kind == KindNonIPsec {
		return nil, SkipNonIPsec
	}

	// For UDP-encapsulated protocols, the payload is the UDP payload.
	payload := ip.Payload
	if ip.Protocol == 17 && len(ip.Payload) >= 8 {
		payload = ip.Payload[8:] // Skip UDP header.
		// For IKE on port 4500, skip the 4-byte non-ESP marker.
		if kind == KindIKE && (srcPort == 4500 || dstPort == 4500) && len(payload) >= 4 {
			payload = payload[4:]
		}
	}

	return &Datagram{
		PacketIndex: pkt.Index,
		Timestamp:   pkt.Timestamp,
		SrcIP:       ip.SrcIP,
		DstIP:       ip.DstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		IPVersion:   ip.Version,
		Kind:        kind,
		Payload:     payload,
		SPI:         spi,
		Sequence:    seq,
		AHICVLen:    ahICVLen,
		Truncated:   ip.Truncated || pkt.CaptureLen < pkt.OrigLen,
	}, ""
}

// Decoder reads packets from a pcap.Reader and yields classified Datagrams.
type Decoder struct {
	reader *pcap.Reader
	stats  *Stats
	format pcap.Format
}

// NewDecoder creates a Decoder from a pcap.Reader.
func NewDecoder(r *pcap.Reader) *Decoder {
	return &Decoder{
		reader: r,
		stats:  newStats(),
		format: r.Format(),
	}
}

// Next returns the next IPsec-relevant datagram. Non-IPsec packets are counted
// and skipped. Returns io.EOF when done.
func (d *Decoder) Next() (*Datagram, error) {
	for {
		pkt, err := d.reader.Next()
		if err != nil {
			return nil, err
		}

		d.stats.Seen++
		d.stats.LinkTypes[pkt.LinkType]++

		dg, reason := DecodePacket(pkt)
		if dg == nil {
			d.stats.Skipped[reason]++
			continue
		}

		d.stats.Decoded++
		d.stats.IPsec++
		return dg, nil
	}
}

// Stats returns the accumulated decode statistics.
func (d *Decoder) Stats() Stats {
	return *d.stats
}

// Format returns the detected capture file format.
func (d *Decoder) Format() pcap.Format {
	return d.format
}
