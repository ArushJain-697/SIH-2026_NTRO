// Package ike parses IKE (Internet Key Exchange) protocol messages from
// captured datagrams. It supports both IKEv1 and IKEv2 headers, SA payload
// parsing with registry-typed proposals, and negotiation matching.
package ike

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/SIH-2026/trace/internal/iana"
)

// Header is a parsed IKE header (common to v1 and v2).
type Header struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	Version      uint8 // Major version: 1 or 2
	Exchange     iana.ExchangeType
	Flags        uint8
	MessageID    uint32
	Length       uint32
	NextPayload  iana.PayloadType
	// IKEv2 flags
	IsResponse  bool
	IsInitiator bool
	// IKEv1 encrypted flag
	Encrypted bool
}

// Proposal represents a parsed IKE SA proposal.
type Proposal struct {
	Number     uint8
	Protocol   uint8 // 1=IKE, 2=AH, 3=ESP
	SPI        []byte
	Transforms []iana.Transform
}

// Payload is a generic parsed IKE payload.
type Payload struct {
	Type     iana.PayloadType
	Data     []byte
	Critical bool
}

// Message is a fully parsed IKE message.
type Message struct {
	Header    Header
	Payloads  []Payload
	Proposals []Proposal
	// Parsed fields
	KEGroup      uint16
	KEPublicLen  int
	NonceLen     int
	Notifies     []Notify
	VendorIDs    int
	AuthMethod   iana.AuthMethod
	CertEncoding uint8
	HasCert      bool
	HasAuth      bool
	Encrypted    bool
	Malformed    string
	PQHybridSeen bool

	// IKEv1 specific
	V1Encryption      uint16
	V1Hash            uint16
	V1AuthMethod      uint16
	V1Group           uint16
	V1KeyBits         uint16
	V1LifeSecs        uint32
	V1LifeKB          uint32
	V1Aggressive      bool
	V1IdentityExposed bool
}

// Notify is a parsed notify payload.
type Notify struct {
	Protocol uint8
	Type     iana.NotifyType
	SPI      []byte
	Data     []byte
}

// ParseHeader parses an IKE header from raw bytes.
func ParseHeader(data []byte) (Header, error) {
	if len(data) < 28 {
		return Header{}, fmt.Errorf("ike: header too short (%d bytes)", len(data))
	}

	h := Header{
		InitiatorSPI: binary.BigEndian.Uint64(data[0:8]),
		ResponderSPI: binary.BigEndian.Uint64(data[8:16]),
		NextPayload:  iana.PayloadType(data[16]),
		Flags:        data[19],
		MessageID:    binary.BigEndian.Uint32(data[20:24]),
		Length:       binary.BigEndian.Uint32(data[24:28]),
	}

	// Version field: major in high nibble, minor in low.
	h.Version = data[17] >> 4

	h.Exchange = iana.ExchangeType(data[18])

	if h.InitiatorSPI == 0 {
		return Header{}, fmt.Errorf("ike: initiator SPI is zero")
	}

	if !iana.IsValidExchange(h.Version, h.Exchange) {
		// Don't reject, just note it — could be a new exchange type.
	}

	if h.Version == 2 {
		h.IsResponse = (h.Flags & 0x20) != 0
		h.IsInitiator = (h.Flags & 0x08) != 0
	} else if h.Version == 1 {
		h.Encrypted = (h.Flags & 0x01) != 0
	}

	return h, nil
}

// ParseMessage parses a complete IKE message including payloads.
func ParseMessage(data []byte) (*Message, error) {
	hdr, err := ParseHeader(data)
	if err != nil {
		return &Message{Header: hdr, Malformed: err.Error()}, nil
	}

	msg := &Message{Header: hdr}

	// Walk the payload chain.
	if int(hdr.Length) > len(data) {
		msg.Malformed = "ike: message length exceeds data"
		return msg, nil
	}

	payloadData := data[28:]
	if int(hdr.Length) <= 28 {
		return msg, nil
	}
	payloadData = data[28:hdr.Length]

	nextPayload := hdr.NextPayload

	// IKEv1 encrypted — stop.
	if hdr.Version == 1 && hdr.Encrypted {
		msg.Encrypted = true
		return msg, nil
	}

	for nextPayload != iana.PayloadNone && len(payloadData) >= 4 {
		// Generic payload header: next(1) + critical(1) + length(2)
		np := iana.PayloadType(payloadData[0])
		critical := (payloadData[1] & 0x80) != 0
		pLen := binary.BigEndian.Uint16(payloadData[2:4])

		if pLen < 4 || int(pLen) > len(payloadData) {
			msg.Malformed = fmt.Sprintf("ike: payload %s length %d invalid", nextPayload, pLen)
			break
		}

		pData := payloadData[4:pLen]

		// Check for SK/SKF — stop the chain (encrypted).
		if nextPayload == iana.PayloadSK || nextPayload == iana.PayloadSKF {
			msg.Encrypted = true
			break
		}

		msg.Payloads = append(msg.Payloads, Payload{
			Type:     nextPayload,
			Data:     pData,
			Critical: critical,
		})

		// Parse specific payloads.
		switch nextPayload {
		case iana.PayloadSA:
			if hdr.Version == 2 {
				proposals := parseSAv2(pData)
				msg.Proposals = proposals
			} else if hdr.Version == 1 {
				parseV1SA(pData, msg)
			}

		case iana.PayloadKE:
			if len(pData) >= 4 {
				msg.KEGroup = binary.BigEndian.Uint16(pData[0:2])
				msg.KEPublicLen = len(pData) - 4
			}

		case iana.PayloadNonce:
			msg.NonceLen = len(pData)

		case iana.PayloadNotify:
			notify := parseNotify(pData)
			msg.Notifies = append(msg.Notifies, notify)
			// Check for PQ hybrid indicators.
			if notify.Type >= 16 { // status notify
				// Additional key exchange indicators
			}

		case iana.PayloadVendorID:
			msg.VendorIDs++

		case iana.PayloadAUTH:
			if len(pData) >= 1 {
				msg.AuthMethod = iana.AuthMethod(pData[0])
				msg.HasAuth = true
			}

		case iana.PayloadCERT:
			if len(pData) >= 1 {
				msg.CertEncoding = pData[0]
				msg.HasCert = true
			}

		case iana.PayloadIDi:
			if hdr.Version == 1 && hdr.Exchange == iana.ExchV1Aggressive {
				msg.V1IdentityExposed = true
				msg.V1Aggressive = true
			}
		}

		payloadData = payloadData[pLen:]
		nextPayload = np
	}

	// Check for additional key exchange transforms in proposals.
	for _, p := range msg.Proposals {
		for _, tr := range p.Transforms {
			if tr.Type >= iana.TypeADDKE6 && tr.Type <= iana.TypeADDKE12 {
				msg.PQHybridSeen = true
			}
		}
	}

	return msg, nil
}

func parseSAv2(data []byte) []Proposal {
	var proposals []Proposal
	for len(data) >= 8 {
		// Proposal: last/more(1), reserved(1), propLen(2), propNum(1), protocolID(1), spiSize(1), numTransforms(1)
		propLen := binary.BigEndian.Uint16(data[2:4])
		if propLen < 8 || int(propLen) > len(data) {
			break
		}

		propNum := data[4]
		protocolID := data[5]
		spiSize := data[6]
		numTransforms := data[7]

		prop := Proposal{
			Number:   propNum,
			Protocol: protocolID,
		}

		offset := 8
		if spiSize > 0 {
			if offset+int(spiSize) > int(propLen) {
				break
			}
			prop.SPI = make([]byte, spiSize)
			copy(prop.SPI, data[offset:offset+int(spiSize)])
			offset += int(spiSize)
		}

		// Parse transforms.
		trData := data[offset:propLen]
		for i := 0; i < int(numTransforms) && len(trData) >= 8; i++ {
			trLen := binary.BigEndian.Uint16(trData[2:4])
			if trLen < 8 || int(trLen) > len(trData) {
				break
			}

			trType := iana.TransformType(trData[4])
			trID := binary.BigEndian.Uint16(trData[6:8])

			// Look for key length attribute (type 14, TV form).
			var keyBits int
			attrData := trData[8:trLen]
			for len(attrData) >= 4 {
				attrType := binary.BigEndian.Uint16(attrData[0:2])
				isTV := (attrType & 0x8000) != 0
				attrNum := attrType & 0x7FFF

				if isTV {
					if attrNum == 14 { // Key Length
						keyBits = int(binary.BigEndian.Uint16(attrData[2:4]))
					}
					attrData = attrData[4:]
				} else {
					aLen := binary.BigEndian.Uint16(attrData[2:4])
					attrData = attrData[4+aLen:]
				}
			}

			tr, _ := iana.Lookup(trType, trID, keyBits)
			prop.Transforms = append(prop.Transforms, tr)

			trData = trData[trLen:]
		}

		proposals = append(proposals, prop)

		if data[0] == 0 { // last proposal
			break
		}
		data = data[propLen:]
	}
	return proposals
}

func parseV1SA(data []byte, msg *Message) {
	// IKEv1 SA: DOI(4) + Situation(4) + proposals...
	if len(data) < 8 {
		return
	}
	propData := data[8:]

	for len(propData) >= 8 {
		propLen := binary.BigEndian.Uint16(propData[2:4])
		if propLen < 8 || int(propLen) > len(propData) {
			break
		}

		// Walk transforms within this proposal.
		spiSize := propData[6]
		offset := 8 + int(spiSize)
		trData := propData[offset:propLen]

		for len(trData) >= 8 {
			trLen := binary.BigEndian.Uint16(trData[2:4])
			if trLen < 8 || int(trLen) > len(trData) {
				break
			}

			// Parse attributes.
			attrData := trData[8:trLen]
			for len(attrData) >= 4 {
				attrType := binary.BigEndian.Uint16(attrData[0:2])
				isTV := (attrType & 0x8000) != 0
				attrNum := attrType & 0x7FFF

				var attrVal uint16
				var tlvVal []byte
				if isTV {
					attrVal = binary.BigEndian.Uint16(attrData[2:4])
					attrData = attrData[4:]
				} else {
					aLen := binary.BigEndian.Uint16(attrData[2:4])
					if int(4+aLen) > len(attrData) {
						break
					}
					tlvVal = attrData[4 : 4+aLen]
					attrData = attrData[4+aLen:]
					_ = tlvVal
				}

				switch attrNum {
				case iana.V1AttrEncryption:
					msg.V1Encryption = attrVal
				case iana.V1AttrHash:
					msg.V1Hash = attrVal
				case iana.V1AttrAuthMethod:
					msg.V1AuthMethod = attrVal
				case iana.V1AttrGroup:
					msg.V1Group = attrVal
				case iana.V1AttrKeyLength:
					msg.V1KeyBits = attrVal
				case iana.V1AttrLifeType:
					// 1=seconds, 2=kilobytes
				case iana.V1AttrLifeDuration:
					if isTV {
						msg.V1LifeSecs = uint32(attrVal)
					} else if len(tlvVal) == 4 {
						msg.V1LifeSecs = binary.BigEndian.Uint32(tlvVal)
					} else if len(tlvVal) == 2 {
						msg.V1LifeSecs = uint32(binary.BigEndian.Uint16(tlvVal))
					}
				}
			}

			if trData[0] == 0 { // last transform
				break
			}
			trData = trData[trLen:]
		}

		if propData[0] == 0 { // last proposal
			break
		}
		propData = propData[propLen:]
	}
}

func parseNotify(data []byte) Notify {
	if len(data) < 4 {
		return Notify{}
	}
	n := Notify{
		Protocol: data[0],
		Type:     iana.NotifyType(binary.BigEndian.Uint16(data[2:4])),
	}
	spiSize := data[1]
	offset := 4
	if spiSize > 0 && offset+int(spiSize) <= len(data) {
		n.SPI = data[offset : offset+int(spiSize)]
		offset += int(spiSize)
	}
	if offset < len(data) {
		n.Data = data[offset:]
	}
	return n
}

// NegotiationResult holds the match between offered and selected proposals.
type NegotiationResult struct {
	Offered    []Proposal
	Selected   *Proposal
	Consistent bool
	KEGroup    uint16
	SelectedDH uint16
	// RetransmitCount tracks retransmitted packets.
	RetransmitCount int
}

// SA represents an IKE Security Association tracked across messages.
type SA struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	Version      uint8
	// Endpoints
	InitiatorIP   net.IP
	InitiatorPort uint16
	ResponderIP   net.IP
	ResponderPort uint16
	// Timing
	FirstTime time.Time
	LastTime  time.Time
	FirstPkt  int
	LastPkt   int
	// Negotiation
	Negotiation NegotiationResult
	// NAT facts
	NATSourceMatch bool
	NATDestMatch   bool
	NATOnPath      *bool // nil = unknown
	UDPEncap       bool
	// Exchanges
	Exchanges []ExchangeRecord
	// Counters
	MalformedCount int
	DuplicateCount int
	// Auth
	AuthMethod iana.AuthMethod
	HasCert    bool
	// IKEv1
	V1Encryption      string
	V1Hash            string
	V1AuthMethod      string
	V1Group           uint16
	V1KeyBits         uint16
	V1LifeSecs        uint32
	V1Aggressive      bool
	V1IdentityExposed bool
	// Features
	FragmentationSupported bool
	PQHybridSeen           bool
	// Messages
	Messages []*Message
}

// ExchangeRecord tracks one exchange in the SA.
type ExchangeRecord struct {
	Exchange  iana.ExchangeType
	MessageID uint32
	Encrypted bool
	PacketIdx int
}

// SATable tracks all IKE SAs keyed by initiator SPI.
type SATable struct {
	SAs map[uint64]*SA
	// Seen tracks (SPIi, messageID, direction hash) for dedup.
	seen map[uint64]map[uint32][]byte
}

// NewSATable creates a new SA table.
func NewSATable() *SATable {
	return &SATable{
		SAs:  make(map[uint64]*SA),
		seen: make(map[uint64]map[uint32][]byte),
	}
}

// Process adds an IKE message to the SA table.
func (t *SATable) Process(msg *Message, srcIP, dstIP net.IP, srcPort, dstPort uint16, pktIdx int, ts time.Time) {
	h := msg.Header
	sa, exists := t.SAs[h.InitiatorSPI]
	if !exists {
		sa = &SA{
			InitiatorSPI:  h.InitiatorSPI,
			Version:       h.Version,
			InitiatorIP:   srcIP,
			InitiatorPort: srcPort,
			ResponderIP:   dstIP,
			ResponderPort: dstPort,
			FirstTime:     ts,
			FirstPkt:      pktIdx,
		}
		t.SAs[h.InitiatorSPI] = sa
	}

	sa.LastTime = ts
	sa.LastPkt = pktIdx
	sa.Messages = append(sa.Messages, msg)

	if h.ResponderSPI != 0 && sa.ResponderSPI == 0 {
		sa.ResponderSPI = h.ResponderSPI
	}

	// Track port float (NAT-T).
	if srcPort == 4500 || dstPort == 4500 {
		sa.UDPEncap = true
	}

	// Update exchange history.
	sa.Exchanges = append(sa.Exchanges, ExchangeRecord{
		Exchange:  h.Exchange,
		MessageID: h.MessageID,
		Encrypted: msg.Encrypted,
		PacketIdx: pktIdx,
	})

	// Malformed counter.
	if msg.Malformed != "" {
		sa.MalformedCount++
	}

	// Collect negotiation data.
	if h.Version == 2 {
		t.processV2(sa, msg, h)
	} else if h.Version == 1 {
		t.processV1(sa, msg, h)
	}
}

func (t *SATable) processV2(sa *SA, msg *Message, h Header) {
	// IKE_SA_INIT: collect offered/selected proposals.
	if h.Exchange == iana.ExchIKE_SA_INIT {
		if !h.IsResponse && len(msg.Proposals) > 0 {
			// Initiator's offers.
			sa.Negotiation.Offered = msg.Proposals
			sa.Negotiation.KEGroup = msg.KEGroup
		} else if h.IsResponse && len(msg.Proposals) > 0 {
			// Responder's selection.
			if len(msg.Proposals) > 0 {
				p := msg.Proposals[0]
				sa.Negotiation.Selected = &p
				// Extract selected DH from the transforms.
				for _, tr := range p.Transforms {
					if tr.Type == iana.TypeDH {
						sa.Negotiation.SelectedDH = tr.ID
					}
				}
			}
		}
	}

	// Collect notify information.
	for _, n := range msg.Notifies {
		switch n.Type {
		case iana.NotifyNAT_DETECTION_SOURCE_IP:
			sa.NATSourceMatch = true
		case iana.NotifyNAT_DETECTION_DESTINATION_IP:
			sa.NATDestMatch = true
		case iana.NotifyIKEV2_FRAGMENTATION_SUPPORTED:
			sa.FragmentationSupported = true
		}
	}

	if msg.HasAuth {
		sa.AuthMethod = msg.AuthMethod
	}
	if msg.HasCert {
		sa.HasCert = true
	}
	if msg.PQHybridSeen {
		sa.PQHybridSeen = true
	}

	// Check consistency.
	if sa.Negotiation.Selected != nil && len(sa.Negotiation.Offered) > 0 {
		sa.Negotiation.Consistent = checkConsistency(sa.Negotiation.Offered, sa.Negotiation.Selected)
	}
}

func (t *SATable) processV1(sa *SA, msg *Message, h Header) {
	if msg.V1Encryption > 0 {
		sa.V1Encryption = iana.V1EncryptionName(msg.V1Encryption, msg.V1KeyBits)
		sa.V1KeyBits = msg.V1KeyBits
	}
	if msg.V1Hash > 0 {
		sa.V1Hash = iana.V1HashName(msg.V1Hash)
	}
	if msg.V1AuthMethod > 0 {
		sa.V1AuthMethod = iana.V1AuthName(msg.V1AuthMethod)
	}
	if msg.V1Group > 0 {
		sa.V1Group = msg.V1Group
	}
	if msg.V1LifeSecs > 0 {
		sa.V1LifeSecs = msg.V1LifeSecs
	}
	if msg.V1Aggressive {
		sa.V1Aggressive = true
	}
	if msg.V1IdentityExposed {
		sa.V1IdentityExposed = true
	}
}

// checkConsistency verifies that the selected proposal was among the offered ones.
func checkConsistency(offered []Proposal, selected *Proposal) bool {
	for _, o := range offered {
		if o.Number == selected.Number && o.Protocol == selected.Protocol {
			return true
		}
	}
	return false
}
