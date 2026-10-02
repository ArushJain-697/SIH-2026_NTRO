// Package testutil provides helpers for building test captures.
package testutil

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/SIH-2026/trace/internal/iana"
)

// CaptureBuilder builds test pcap files with synthetic IKE and ESP packets.
type CaptureBuilder struct {
	buf       bytes.Buffer
	pktCount  int
	startTime time.Time
}

// NewCapture creates a new capture builder with a classic pcap header.
func NewCapture() *CaptureBuilder {
	cb := &CaptureBuilder{
		startTime: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}

	// Write pcap global header (little-endian, microseconds).
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4) // magic
	binary.LittleEndian.PutUint16(hdr[4:6], 2)          // major
	binary.LittleEndian.PutUint16(hdr[6:8], 4)          // minor
	binary.LittleEndian.PutUint32(hdr[8:12], 0)         // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0)        // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)    // snaplen
	binary.LittleEndian.PutUint32(hdr[20:24], 1)        // link type = Ethernet
	cb.buf.Write(hdr[:])

	return cb
}

// addPacket writes one pcap record.
func (cb *CaptureBuilder) addPacket(data []byte) {
	ts := cb.startTime.Add(time.Duration(cb.pktCount) * 100 * time.Millisecond)
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(data)))
	cb.buf.Write(hdr[:])
	cb.buf.Write(data)
	cb.pktCount++
}

// wrapEthernet wraps IP payload in Ethernet.
func wrapEthernet(etherType uint16, ipPayload []byte) []byte {
	frame := make([]byte, 14+len(ipPayload))
	// dst and src MAC (zeros)
	frame[12] = byte(etherType >> 8)
	frame[13] = byte(etherType)
	copy(frame[14:], ipPayload)
	return frame
}

// wrapIPv4UDP wraps a UDP payload in IPv4+UDP.
func wrapIPv4UDP(src, dst net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen

	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // version + IHL
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))

	copy(pkt[28:], payload)
	return pkt
}

// wrapIPv4ESP wraps ESP in IPv4.
func wrapIPv4ESP(src, dst net.IP, spi, seq uint32, payload []byte) []byte {
	espLen := 8 + len(payload)
	totalLen := 20 + espLen

	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 50 // ESP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())

	binary.BigEndian.PutUint32(pkt[20:24], spi)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	copy(pkt[28:], payload)
	return pkt
}

// AddIKEv2SAINIT adds an IKEv2 IKE_SA_INIT exchange (request and response).
func (cb *CaptureBuilder) AddIKEv2SAINIT(src, dst net.IP, initiatorSPI uint64, responderSPI uint64, encID uint16, encKeyBits int, dhGroup uint16) {
	// Request (initiator → responder)
	reqPayload := buildIKEv2SAINITRequest(initiatorSPI, encID, encKeyBits, dhGroup)
	ipData := wrapIPv4UDP(src, dst, 500, 500, reqPayload)
	cb.addPacket(wrapEthernet(0x0800, ipData))

	// Response (responder → initiator)
	respPayload := buildIKEv2SAINITResponse(initiatorSPI, responderSPI, encID, encKeyBits, dhGroup)
	ipData = wrapIPv4UDP(dst, src, 500, 500, respPayload)
	cb.addPacket(wrapEthernet(0x0800, ipData))
}

// AddESPPackets adds n ESP packets.
func (cb *CaptureBuilder) AddESPPackets(src, dst net.IP, spi uint32, n int, payloadSize int) {
	for i := 0; i < n; i++ {
		payload := make([]byte, payloadSize)
		ipData := wrapIPv4ESP(src, dst, spi, uint32(i+1), payload)
		cb.addPacket(wrapEthernet(0x0800, ipData))
	}
}

// Bytes returns the built pcap file.
func (cb *CaptureBuilder) Bytes() []byte {
	return cb.buf.Bytes()
}

// buildIKEv2SAINITRequest builds a minimal IKE_SA_INIT request.
func buildIKEv2SAINITRequest(initiatorSPI uint64, encID uint16, encKeyBits int, dhGroup uint16) []byte {
	// IKE header: 28 bytes
	// SA payload with one proposal
	// KE payload
	// Nonce payload

	var sa bytes.Buffer

	// SA payload body: one proposal with ENCR, PRF, INTEG (if not AEAD), DH, ESN
	proposal := buildProposal(1, 1, encID, encKeyBits, dhGroup, false) // initiator sends offers
	sa.Write(proposal)

	// KE payload
	var ke bytes.Buffer
	binary.Write(&ke, binary.BigEndian, dhGroup)   // group
	binary.Write(&ke, binary.BigEndian, uint16(0)) // reserved
	ke.Write(make([]byte, 256))                    // public value

	// Nonce payload
	nonce := make([]byte, 32)

	// Build payload chain
	saPayload := buildPayload(iana.PayloadSA, iana.PayloadKE, sa.Bytes())
	kePayload := buildPayload(iana.PayloadKE, iana.PayloadNonce, ke.Bytes())
	noncePayload := buildPayload(iana.PayloadNonce, iana.PayloadNone, nonce)

	payloads := append(saPayload, kePayload...)
	payloads = append(payloads, noncePayload...)

	return buildIKEHeader(initiatorSPI, 0, 2, iana.ExchIKE_SA_INIT, 0x08, 0, iana.PayloadSA, payloads)
}

// buildIKEv2SAINITResponse builds a minimal IKE_SA_INIT response.
func buildIKEv2SAINITResponse(initiatorSPI, responderSPI uint64, encID uint16, encKeyBits int, dhGroup uint16) []byte {
	var sa bytes.Buffer
	proposal := buildProposal(1, 1, encID, encKeyBits, dhGroup, true) // responder selects
	sa.Write(proposal)

	var ke bytes.Buffer
	binary.Write(&ke, binary.BigEndian, dhGroup)
	binary.Write(&ke, binary.BigEndian, uint16(0))
	ke.Write(make([]byte, 256))

	nonce := make([]byte, 32)

	saPayload := buildPayload(iana.PayloadSA, iana.PayloadKE, sa.Bytes())
	kePayload := buildPayload(iana.PayloadKE, iana.PayloadNonce, ke.Bytes())
	noncePayload := buildPayload(iana.PayloadNonce, iana.PayloadNone, nonce)

	payloads := append(saPayload, kePayload...)
	payloads = append(payloads, noncePayload...)

	return buildIKEHeader(initiatorSPI, responderSPI, 2, iana.ExchIKE_SA_INIT, 0x20, 0, iana.PayloadSA, payloads)
}

func buildIKEHeader(spiI, spiR uint64, version uint8, exchange iana.ExchangeType, flags uint8, msgID uint32, nextPayload iana.PayloadType, payloads []byte) []byte {
	length := uint32(28 + len(payloads))
	hdr := make([]byte, 28)
	binary.BigEndian.PutUint64(hdr[0:8], spiI)
	binary.BigEndian.PutUint64(hdr[8:16], spiR)
	hdr[16] = byte(nextPayload)
	hdr[17] = (version << 4) | 0 // major.minor
	hdr[18] = byte(exchange)
	hdr[19] = flags
	binary.BigEndian.PutUint32(hdr[20:24], msgID)
	binary.BigEndian.PutUint32(hdr[24:28], length)
	return append(hdr, payloads...)
}

func buildPayload(typ, next iana.PayloadType, data []byte) []byte {
	length := uint16(4 + len(data))
	hdr := make([]byte, 4)
	hdr[0] = byte(next)
	hdr[1] = 0 // critical bit
	binary.BigEndian.PutUint16(hdr[2:4], length)
	return append(hdr, data...)
}

func buildProposal(propNum, protoID uint8, encID uint16, encKeyBits int, dhGroup uint16, isLast bool) []byte {
	var transforms bytes.Buffer

	numTransforms := 0

	// ENCR transform
	encTr := buildTransform(iana.TypeEncryption, encID, encKeyBits, false)
	transforms.Write(encTr)
	numTransforms++

	// PRF: SHA-384
	prfTr := buildTransform(iana.TypePRF, 6, 0, false) // PRF-HMAC-SHA2-384
	transforms.Write(prfTr)
	numTransforms++

	// Check if AEAD
	enc, _ := iana.Lookup(iana.TypeEncryption, encID, encKeyBits)
	if !enc.AEAD {
		// INTEG: HMAC-SHA2-256-128
		integTr := buildTransform(iana.TypeIntegrity, 12, 0, false)
		transforms.Write(integTr)
		numTransforms++
	}

	// DH
	dhTr := buildTransform(iana.TypeDH, dhGroup, 0, false)
	transforms.Write(dhTr)
	numTransforms++

	// ESN (last transform)
	esnTr := buildTransform(iana.TypeESN, 0, 0, true) // No-ESN, last
	transforms.Write(esnTr)
	numTransforms++

	trData := transforms.Bytes()
	propLen := 8 + len(trData) // proposal header + transforms

	prop := make([]byte, 8)
	if isLast {
		prop[0] = 0 // last proposal
	} else {
		prop[0] = 2 // more proposals
	}
	binary.BigEndian.PutUint16(prop[2:4], uint16(propLen))
	prop[4] = propNum
	prop[5] = protoID
	prop[6] = 0 // SPI size
	prop[7] = byte(numTransforms)

	return append(prop, trData...)
}

func buildTransform(typ iana.TransformType, id uint16, keyBits int, isLast bool) []byte {
	var attrs bytes.Buffer
	if keyBits > 0 {
		// Key Length attribute (type 14, TV form)
		attr := make([]byte, 4)
		binary.BigEndian.PutUint16(attr[0:2], 0x800E) // TV, type 14
		binary.BigEndian.PutUint16(attr[2:4], uint16(keyBits))
		attrs.Write(attr)
	}

	trLen := 8 + attrs.Len()
	tr := make([]byte, 8)
	if isLast {
		tr[0] = 0 // last
	} else {
		tr[0] = 3 // more
	}
	binary.BigEndian.PutUint16(tr[2:4], uint16(trLen))
	tr[4] = byte(typ)
	binary.BigEndian.PutUint16(tr[6:8], id)

	return append(tr, attrs.Bytes()...)
}

// BuildIKEv2GCMCapture creates a complete IKEv2 AES-256-GCM capture.
func BuildIKEv2GCMCapture() []byte {
	cb := NewCapture()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)

	// IKE_SA_INIT with AES-256-GCM-16 (ID=20) and ECP-256 (group 19)
	cb.AddIKEv2SAINIT(src, dst, 0x1122334455667788, 0xAABBCCDDEEFF0011, 20, 256, 19)

	// Some ESP traffic
	cb.AddESPPackets(src, dst, 0x11111111, 10, 128)
	cb.AddESPPackets(dst, src, 0x22222222, 10, 128)

	return cb.Bytes()
}

// BuildIKEv2CBCCapture creates an IKEv2 AES-256-CBC capture.
func BuildIKEv2CBCCapture() []byte {
	cb := NewCapture()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)

	// IKE_SA_INIT with AES-CBC-256 (ID=12) and MODP-2048 (group 14)
	cb.AddIKEv2SAINIT(src, dst, 0x2233445566778899, 0xBBCCDDEEFF001122, 12, 256, 14)

	cb.AddESPPackets(src, dst, 0x33333333, 5, 96)
	cb.AddESPPackets(dst, src, 0x44444444, 5, 96)

	return cb.Bytes()
}

// BuildNonIPsecCapture creates a capture with only TCP traffic.
func BuildNonIPsecCapture() []byte {
	cb := NewCapture()
	src := net.IPv4(192, 168, 1, 1)
	dst := net.IPv4(192, 168, 1, 2)

	// TCP packets (protocol 6)
	for i := 0; i < 5; i++ {
		tcpLen := 20 + 64
		totalLen := 20 + tcpLen
		pkt := make([]byte, totalLen)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
		pkt[9] = 6 // TCP
		copy(pkt[12:16], src.To4())
		copy(pkt[16:20], dst.To4())
		cb.addPacket(wrapEthernet(0x0800, pkt))
	}

	return cb.Bytes()
}
