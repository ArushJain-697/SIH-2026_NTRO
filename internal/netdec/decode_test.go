package netdec

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/SIH-2026/trace/internal/pcap"
)

// buildEthernetIPv4UDP builds a minimal Ethernet → IPv4 → UDP packet.
func buildEthernetIPv4UDP(src, dst net.IP, srcPort, dstPort uint16, udpPayload []byte) []byte {
	var buf bytes.Buffer

	// Ethernet: dst(6) + src(6) + etherType(2) = 14 bytes.
	buf.Write(make([]byte, 12))
	buf.Write([]byte{0x08, 0x00}) // IPv4

	writeIPv4UDP(&buf, src, dst, srcPort, dstPort, udpPayload)
	return buf.Bytes()
}

// buildEthernetIPv6UDP builds a minimal Ethernet → IPv6 → UDP packet.
func buildEthernetIPv6UDP(src, dst net.IP, srcPort, dstPort uint16, udpPayload []byte) []byte {
	var buf bytes.Buffer

	buf.Write(make([]byte, 12))
	buf.Write([]byte{0x86, 0xDD}) // IPv6

	writeIPv6UDP(&buf, src, dst, srcPort, dstPort, udpPayload)
	return buf.Bytes()
}

func writeIPv4UDP(buf *bytes.Buffer, src, dst net.IP, srcPort, dstPort uint16, udpPayload []byte) {
	udpLen := 8 + len(udpPayload)
	totalLen := 20 + udpLen

	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version + IHL
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	ipHdr[9] = 17 // protocol = UDP
	copy(ipHdr[12:16], src.To4())
	copy(ipHdr[16:20], dst.To4())
	buf.Write(ipHdr)

	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHdr[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(udpLen))
	buf.Write(udpHdr)
	buf.Write(udpPayload)
}

func writeIPv6UDP(buf *bytes.Buffer, src, dst net.IP, srcPort, dstPort uint16, udpPayload []byte) {
	udpLen := 8 + len(udpPayload)

	ipHdr := make([]byte, 40)
	ipHdr[0] = 0x60 // version
	binary.BigEndian.PutUint16(ipHdr[4:6], uint16(udpLen))
	ipHdr[6] = 17 // next header = UDP
	ipHdr[7] = 64 // hop limit
	copy(ipHdr[8:24], src.To16())
	copy(ipHdr[24:40], dst.To16())
	buf.Write(ipHdr)

	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHdr[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(udpLen))
	buf.Write(udpHdr)
	buf.Write(udpPayload)
}

// buildEthernetIPv4ESP builds a minimal Ethernet → IPv4 → ESP packet.
func buildEthernetIPv4ESP(src, dst net.IP, spi, seq uint32) []byte {
	var buf bytes.Buffer

	buf.Write(make([]byte, 12))
	buf.Write([]byte{0x08, 0x00})

	espPayload := make([]byte, 32) // SPI + seq + some encrypted data
	binary.BigEndian.PutUint32(espPayload[0:4], spi)
	binary.BigEndian.PutUint32(espPayload[4:8], seq)

	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(20+len(espPayload)))
	ipHdr[9] = 50 // protocol = ESP
	copy(ipHdr[12:16], src.To4())
	copy(ipHdr[16:20], dst.To4())
	buf.Write(ipHdr)
	buf.Write(espPayload)
	return buf.Bytes()
}

// buildEthernetIPv4AH builds a minimal Ethernet → IPv4 → AH packet.
func buildEthernetIPv4AH(src, dst net.IP, spi, seq uint32, icvLen int) []byte {
	var buf bytes.Buffer

	buf.Write(make([]byte, 12))
	buf.Write([]byte{0x08, 0x00})

	// AH header: next(1) + payloadLen(1) + reserved(2) + SPI(4) + seq(4) + ICV(icvLen)
	ahPayloadLen := (icvLen / 4) + 1 // (ICV/4 + 1)
	ahHdr := make([]byte, 12+icvLen)
	ahHdr[0] = 59 // next header = no next header
	ahHdr[1] = byte(ahPayloadLen)
	binary.BigEndian.PutUint32(ahHdr[4:8], spi)
	binary.BigEndian.PutUint32(ahHdr[8:12], seq)

	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(20+len(ahHdr)))
	ipHdr[9] = 51 // protocol = AH
	copy(ipHdr[12:16], src.To4())
	copy(ipHdr[16:20], dst.To4())
	buf.Write(ipHdr)
	buf.Write(ahHdr)
	return buf.Bytes()
}

func TestDecodeLinkEthernet(t *testing.T) {
	// Minimal Ethernet frame with IPv4 payload.
	frame := make([]byte, 20)
	frame[12] = 0x08
	frame[13] = 0x00
	frame[14] = 0x45 // IPv4 version

	payload, etherType, err := DecodeLink(frame, pcap.LinkEthernet)
	if err != nil {
		t.Fatalf("DecodeLink: %v", err)
	}
	if etherType != 0x0800 {
		t.Errorf("etherType = 0x%04x, want 0x0800", etherType)
	}
	if payload[0]>>4 != 4 {
		t.Errorf("payload IP version = %d, want 4", payload[0]>>4)
	}
}

func TestDecodeLinkVLAN(t *testing.T) {
	// Ethernet with 802.1Q VLAN tag.
	frame := make([]byte, 24)
	frame[12] = 0x81
	frame[13] = 0x00 // 802.1Q
	// VLAN tag: 2 bytes TCI + 2 bytes inner EtherType
	frame[16] = 0x08
	frame[17] = 0x00 // IPv4
	frame[18] = 0x45

	payload, etherType, err := DecodeLink(frame, pcap.LinkEthernet)
	if err != nil {
		t.Fatalf("DecodeLink: %v", err)
	}
	if etherType != 0x0800 {
		t.Errorf("etherType = 0x%04x, want 0x0800", etherType)
	}
	if payload[0]>>4 != 4 {
		t.Errorf("payload IP version = %d, want 4", payload[0]>>4)
	}
}

func TestDecodeLinkSLL(t *testing.T) {
	frame := make([]byte, 20)
	frame[14] = 0x08
	frame[15] = 0x00
	frame[16] = 0x45

	payload, etherType, err := DecodeLink(frame, pcap.LinkLinuxSLL)
	if err != nil {
		t.Fatalf("DecodeLink: %v", err)
	}
	if etherType != 0x0800 {
		t.Errorf("etherType = 0x%04x, want 0x0800", etherType)
	}
	if payload[0]>>4 != 4 {
		t.Error("not IPv4")
	}
}

func TestDecodeLinkSLL2(t *testing.T) {
	frame := make([]byte, 24)
	frame[0] = 0x08
	frame[1] = 0x00
	frame[20] = 0x45

	payload, etherType, err := DecodeLink(frame, pcap.LinkLinuxSLL2)
	if err != nil {
		t.Fatalf("DecodeLink: %v", err)
	}
	if etherType != 0x0800 {
		t.Errorf("etherType = 0x%04x, want 0x0800", etherType)
	}
	if payload[0]>>4 != 4 {
		t.Error("not IPv4")
	}
}

func TestDecodeLinkNull(t *testing.T) {
	// IPv4 payload after 4-byte null header.
	frame := make([]byte, 24)
	frame[4] = 0x45 // IPv4 version nibble

	payload, etherType, err := DecodeLink(frame, pcap.LinkNull)
	if err != nil {
		t.Fatalf("DecodeLink: %v", err)
	}
	if etherType != 0x0800 {
		t.Errorf("etherType = 0x%04x, want 0x0800", etherType)
	}
	if payload[0]>>4 != 4 {
		t.Error("not IPv4")
	}
}

func TestDecodeLinkRawIP(t *testing.T) {
	// IPv4 raw.
	frame := []byte{0x45, 0x00}
	payload, etherType, err := DecodeLink(frame, pcap.LinkRawIP)
	if err != nil {
		t.Fatalf("DecodeLink: %v", err)
	}
	if etherType != 0x0800 {
		t.Errorf("etherType = 0x%04x, want 0x0800", etherType)
	}
	if payload[0] != 0x45 {
		t.Error("wrong payload")
	}
}

func TestDecodeLinkUnsupported(t *testing.T) {
	_, _, err := DecodeLink([]byte{0x00}, pcap.LinkType(999))
	ult, ok := err.(UnsupportedLinkType)
	if !ok {
		t.Fatalf("err type = %T, want UnsupportedLinkType", err)
	}
	if ult.Type != 999 {
		t.Errorf("type = %d, want 999", ult.Type)
	}
}

func TestSamePayloadAcrossLinkTypes(t *testing.T) {
	// Build the same IPv4 UDP packet wrapped in different link types.
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	udpPayload := []byte("hello")

	// Ethernet.
	ethPkt := buildEthernetIPv4UDP(src, dst, 500, 500, udpPayload)
	ethIP, ethET, err := DecodeLink(ethPkt, pcap.LinkEthernet)
	if err != nil {
		t.Fatalf("Ethernet: %v", err)
	}

	// SLL.
	sllPkt := make([]byte, 16)
	sllPkt[14] = 0x08
	sllPkt[15] = 0x00
	sllPkt = append(sllPkt, ethPkt[14:]...) // IP payload is the same
	sllIP, sllET, err := DecodeLink(sllPkt, pcap.LinkLinuxSLL)
	if err != nil {
		t.Fatalf("SLL: %v", err)
	}

	if ethET != sllET {
		t.Errorf("EtherType mismatch: eth=0x%04x sll=0x%04x", ethET, sllET)
	}

	// Same IP payload.
	if !bytes.Equal(ethIP, sllIP) {
		t.Error("IP payloads differ between Ethernet and SLL")
	}
}

func TestClassifyIKEPort500(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	ikePayload := make([]byte, 28) // dummy IKE header
	pkt := buildEthernetIPv4UDP(src, dst, 500, 500, ikePayload)

	dg, reason := DecodePacket(pcap.Packet{Data: pkt, LinkType: pcap.LinkEthernet})
	if dg == nil {
		t.Fatalf("DecodePacket returned nil, reason=%s", reason)
	}
	if dg.Kind != KindIKE {
		t.Errorf("kind = %v, want IKE", dg.Kind)
	}
}

func TestClassifyESPRaw(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	pkt := buildEthernetIPv4ESP(src, dst, 0x12345678, 1)

	dg, reason := DecodePacket(pcap.Packet{Data: pkt, LinkType: pcap.LinkEthernet})
	if dg == nil {
		t.Fatalf("DecodePacket returned nil, reason=%s", reason)
	}
	if dg.Kind != KindESP {
		t.Errorf("kind = %v, want ESP", dg.Kind)
	}
	if dg.SPI != 0x12345678 {
		t.Errorf("SPI = 0x%08x, want 0x12345678", dg.SPI)
	}
	if dg.Sequence != 1 {
		t.Errorf("seq = %d, want 1", dg.Sequence)
	}
}

func TestClassifyAH(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	pkt := buildEthernetIPv4AH(src, dst, 0xAABBCCDD, 42, 12)

	dg, reason := DecodePacket(pcap.Packet{Data: pkt, LinkType: pcap.LinkEthernet})
	if dg == nil {
		t.Fatalf("DecodePacket returned nil, reason=%s", reason)
	}
	if dg.Kind != KindAH {
		t.Errorf("kind = %v, want AH", dg.Kind)
	}
	if dg.SPI != 0xAABBCCDD {
		t.Errorf("SPI = 0x%08x, want 0xAABBCCDD", dg.SPI)
	}
	if dg.AHICVLen != 12 {
		t.Errorf("AHICVLen = %d, want 12", dg.AHICVLen)
	}
}

func TestClassifyNATKeepalive(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	pkt := buildEthernetIPv4UDP(src, dst, 4500, 4500, []byte{0xFF})

	dg, reason := DecodePacket(pcap.Packet{Data: pkt, LinkType: pcap.LinkEthernet})
	if dg == nil {
		t.Fatalf("DecodePacket returned nil, reason=%s", reason)
	}
	if dg.Kind != KindNATKeepalive {
		t.Errorf("kind = %v, want NAT-Keepalive", dg.Kind)
	}
}

func TestClassifyNATTIKE(t *testing.T) {
	// UDP 4500 with non-ESP marker (4 zero bytes) → IKE.
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	payload := make([]byte, 32)
	// First 4 bytes = 0x00000000 (non-ESP marker), rest is IKE.
	pkt := buildEthernetIPv4UDP(src, dst, 4500, 4500, payload)

	dg, reason := DecodePacket(pcap.Packet{Data: pkt, LinkType: pcap.LinkEthernet})
	if dg == nil {
		t.Fatalf("DecodePacket returned nil, reason=%s", reason)
	}
	if dg.Kind != KindIKE {
		t.Errorf("kind = %v, want IKE", dg.Kind)
	}
}

func TestClassifyESPInUDP(t *testing.T) {
	// UDP 4500 with non-zero SPI → ESP-in-UDP.
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	payload := make([]byte, 32)
	binary.BigEndian.PutUint32(payload[0:4], 0x12345678) // non-zero SPI
	binary.BigEndian.PutUint32(payload[4:8], 1)          // sequence
	pkt := buildEthernetIPv4UDP(src, dst, 4500, 4500, payload)

	dg, reason := DecodePacket(pcap.Packet{Data: pkt, LinkType: pcap.LinkEthernet})
	if dg == nil {
		t.Fatalf("DecodePacket returned nil, reason=%s", reason)
	}
	if dg.Kind != KindESP {
		t.Errorf("kind = %v, want ESP", dg.Kind)
	}
	if dg.SPI != 0x12345678 {
		t.Errorf("SPI = 0x%08x, want 0x12345678", dg.SPI)
	}
}

func TestClassifyIPv6IKE(t *testing.T) {
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")
	ikePayload := make([]byte, 28)
	pkt := buildEthernetIPv6UDP(src, dst, 500, 500, ikePayload)

	dg, reason := DecodePacket(pcap.Packet{Data: pkt, LinkType: pcap.LinkEthernet})
	if dg == nil {
		t.Fatalf("DecodePacket returned nil, reason=%s", reason)
	}
	if dg.Kind != KindIKE {
		t.Errorf("kind = %v, want IKE", dg.Kind)
	}
	if dg.IPVersion != 6 {
		t.Errorf("IPVersion = %d, want 6", dg.IPVersion)
	}
}

func TestClassifyNonIPsecSkipped(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	pkt := buildEthernetIPv4UDP(src, dst, 80, 12345, []byte("HTTP"))

	dg, reason := DecodePacket(pcap.Packet{Data: pkt, LinkType: pcap.LinkEthernet})
	if dg != nil {
		t.Errorf("expected nil datagram for non-IPsec, got kind=%v", dg.Kind)
	}
	if reason != SkipNonIPsec {
		t.Errorf("reason = %s, want non_ipsec", reason)
	}
}

func TestSnaplenTruncated(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	pkt := buildEthernetIPv4ESP(src, dst, 0x11111111, 1)

	dg, reason := DecodePacket(pcap.Packet{
		Data:       pkt,
		LinkType:   pcap.LinkEthernet,
		CaptureLen: uint32(len(pkt)),
		OrigLen:    uint32(len(pkt) + 100), // was longer
	})
	if dg == nil {
		t.Fatalf("DecodePacket returned nil, reason=%s", reason)
	}
	if !dg.Truncated {
		t.Error("expected Truncated = true")
	}
}

func TestClassifyIPsecV4V6Same(t *testing.T) {
	// Verify that the same IKE message gives the same classification on v4 and v6.
	ikePayload := make([]byte, 28)

	src4 := net.IPv4(10, 0, 0, 1)
	dst4 := net.IPv4(10, 0, 0, 2)
	pkt4 := buildEthernetIPv4UDP(src4, dst4, 500, 500, ikePayload)
	dg4, _ := DecodePacket(pcap.Packet{Data: pkt4, LinkType: pcap.LinkEthernet})

	src6 := net.ParseIP("2001:db8::1")
	dst6 := net.ParseIP("2001:db8::2")
	pkt6 := buildEthernetIPv6UDP(src6, dst6, 500, 500, ikePayload)
	dg6, _ := DecodePacket(pcap.Packet{Data: pkt6, LinkType: pcap.LinkEthernet})

	if dg4 == nil || dg6 == nil {
		t.Fatal("both should decode")
	}
	if dg4.Kind != dg6.Kind {
		t.Errorf("v4 kind=%v, v6 kind=%v", dg4.Kind, dg6.Kind)
	}
}
