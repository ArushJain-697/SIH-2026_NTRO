package pcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// buildClassicPcap creates a minimal classic pcap file with the given parameters.
func buildClassicPcap(t *testing.T, order binary.ByteOrder, nanos bool, linkType LinkType, packets [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer

	// Magic: the canonical value is always the same; the byte order it's written
	// in is what determines the detected endianness.
	// LE file: PutUint32(LE, 0xa1b2c3d4) → bytes [d4,c3,b2,a1] → LE.Uint32 = 0xa1b2c3d4
	// BE file: PutUint32(BE, 0xa1b2c3d4) → bytes [a1,b2,c3,d4] → LE.Uint32 = 0xd4c3b2a1
	var magic uint32
	if nanos {
		magic = 0xa1b23c4d
	} else {
		magic = 0xa1b2c3d4
	}

	var hdr [24]byte
	order.PutUint32(hdr[0:4], magic)
	order.PutUint16(hdr[4:6], 2)       // major
	order.PutUint16(hdr[6:8], 4)       // minor
	order.PutUint32(hdr[8:12], 0)      // thiszone
	order.PutUint32(hdr[12:16], 0)     // sigfigs
	order.PutUint32(hdr[16:20], 65535) // snaplen
	order.PutUint32(hdr[20:24], uint32(linkType))
	buf.Write(hdr[:])

	// Packets
	for i, pkt := range packets {
		var rec [16]byte
		order.PutUint32(rec[0:4], uint32(1000+i)) // ts_sec
		order.PutUint32(rec[4:8], 0)              // ts_usec
		order.PutUint32(rec[8:12], uint32(len(pkt)))
		order.PutUint32(rec[12:16], uint32(len(pkt)))
		buf.Write(rec[:])
		buf.Write(pkt)
	}

	return buf.Bytes()
}

func TestClassicPcapAllFourMagics(t *testing.T) {
	testPkt := []byte{0x01, 0x02, 0x03, 0x04}
	orders := []struct {
		name  string
		order binary.ByteOrder
	}{
		{"LittleEndian", binary.LittleEndian},
		{"BigEndian", binary.BigEndian},
	}
	nanoOpts := []struct {
		name  string
		nanos bool
	}{
		{"Micros", false},
		{"Nanos", true},
	}

	for _, o := range orders {
		for _, n := range nanoOpts {
			t.Run(o.name+"/"+n.name, func(t *testing.T) {
				data := buildClassicPcap(t, o.order, n.nanos, LinkEthernet, [][]byte{testPkt})
				rd, err := Open(bytes.NewReader(data))
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if rd.Format() != FormatClassicPcap {
					t.Errorf("format = %v, want pcap", rd.Format())
				}

				pkt, err := rd.Next()
				if err != nil {
					t.Fatalf("Next: %v", err)
				}
				if !bytes.Equal(pkt.Data, testPkt) {
					t.Errorf("data = %x, want %x", pkt.Data, testPkt)
				}
				if pkt.LinkType != LinkEthernet {
					t.Errorf("linkType = %d, want %d", pkt.LinkType, LinkEthernet)
				}
				if pkt.Index != 0 {
					t.Errorf("index = %d, want 0", pkt.Index)
				}

				_, err = rd.Next()
				if err != io.EOF {
					t.Errorf("second Next = %v, want EOF", err)
				}
			})
		}
	}
}

func TestClassicPcapFCSBitsIgnored(t *testing.T) {
	// Link type with FCS bits set in high nibble.
	data := buildClassicPcap(t, binary.LittleEndian, false, LinkType(0x10000001), [][]byte{{0xAA}})
	rd, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pkt, err := rd.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if pkt.LinkType != LinkEthernet {
		t.Errorf("linkType = %d, want %d (Ethernet with FCS bits stripped)", pkt.LinkType, LinkEthernet)
	}
}

func TestClassicPcapTruncation(t *testing.T) {
	pkts := [][]byte{{0x01, 0x02}, {0x03, 0x04}}
	data := buildClassicPcap(t, binary.LittleEndian, false, LinkEthernet, pkts)

	// Truncate mid-second-record.
	truncated := data[:len(data)-1]
	rd, err := Open(bytes.NewReader(truncated))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	pkt, err := rd.Next()
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	if !bytes.Equal(pkt.Data, pkts[0]) {
		t.Errorf("first pkt data = %x, want %x", pkt.Data, pkts[0])
	}

	_, err = rd.Next()
	if err != ErrTruncated {
		t.Errorf("second Next = %v, want ErrTruncated", err)
	}
}

func TestOpenTextFile(t *testing.T) {
	_, err := Open(bytes.NewReader([]byte("This is not a pcap file")))
	if err != ErrFormat {
		t.Errorf("Open text = %v, want ErrFormat", err)
	}
}

func TestOpenEmptyFile(t *testing.T) {
	_, err := Open(bytes.NewReader(nil))
	if err != ErrFormat {
		t.Errorf("Open empty = %v, want ErrFormat", err)
	}
}

func TestClassicPcapAbsurdLength(t *testing.T) {
	data := buildClassicPcap(t, binary.LittleEndian, false, LinkEthernet, [][]byte{{0xAA}})
	// Overwrite the capLen of the first record to be huge.
	binary.LittleEndian.PutUint32(data[24+8:24+12], maxRecordLen+1)

	rd, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, err = rd.Next()
	if err != ErrFormat {
		t.Errorf("Next = %v, want ErrFormat", err)
	}
}

func TestClassicPcapNanosTimestamp(t *testing.T) {
	data := buildClassicPcap(t, binary.LittleEndian, true, LinkEthernet, [][]byte{{0xAA}})
	// Set ts_sec=1000, ts_nsec=123456789
	binary.LittleEndian.PutUint32(data[24:28], 1000)
	binary.LittleEndian.PutUint32(data[28:32], 123456789)

	rd, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pkt, err := rd.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	expected := time.Unix(1000, 123456789)
	if !pkt.Timestamp.Equal(expected) {
		t.Errorf("timestamp = %v, want %v", pkt.Timestamp, expected)
	}
}

func TestClassicPcapMultiplePackets(t *testing.T) {
	pkts := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05},
		{0x06},
	}
	data := buildClassicPcap(t, binary.BigEndian, false, LinkEthernet, pkts)
	rd, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	for i, expected := range pkts {
		pkt, err := rd.Next()
		if err != nil {
			t.Fatalf("Next[%d]: %v", i, err)
		}
		if !bytes.Equal(pkt.Data, expected) {
			t.Errorf("pkt[%d] data = %x, want %x", i, pkt.Data, expected)
		}
		if pkt.Index != i {
			t.Errorf("pkt[%d] index = %d", i, pkt.Index)
		}
	}

	_, err = rd.Next()
	if err != io.EOF {
		t.Errorf("final Next = %v, want EOF", err)
	}
}

// buildPcapNG creates a minimal pcapng file with one section, given interfaces and packets.
func buildPcapNG(t *testing.T, order binary.ByteOrder, interfaces []ngTestIface, packets []ngTestPacket) []byte {
	t.Helper()
	var buf bytes.Buffer

	// Section Header Block.
	writeSHB(t, &buf, order)

	// Interface Description Blocks.
	for _, iface := range interfaces {
		writeIDB(t, &buf, order, iface)
	}

	// Enhanced Packet Blocks.
	for _, pkt := range packets {
		writeEPB(t, &buf, order, pkt)
	}

	return buf.Bytes()
}

type ngTestIface struct {
	linkType LinkType
	tsResol  *uint8 // nil = default
}

type ngTestPacket struct {
	ifaceID uint32
	tsSec   uint32
	tsUsec  uint32
	data    []byte
}

func writeSHB(t *testing.T, buf *bytes.Buffer, order binary.ByteOrder) {
	t.Helper()
	// Block: type(4) + length(4) + BOM(4) + major(2) + minor(2) + sectionLen(8) + trailer(4) = 28
	totalLen := uint32(28)
	var block [28]byte
	order.PutUint32(block[0:4], pcapngSHBType)
	order.PutUint32(block[4:8], totalLen)
	// BOM
	if order == binary.LittleEndian {
		order.PutUint32(block[8:12], 0x1A2B3C4D)
	} else {
		order.PutUint32(block[8:12], 0x1A2B3C4D)
	}
	order.PutUint16(block[12:14], 1) // major
	order.PutUint16(block[14:16], 0) // minor
	// section length = -1 (unspecified)
	order.PutUint32(block[16:20], 0xFFFFFFFF)
	order.PutUint32(block[20:24], 0xFFFFFFFF)
	order.PutUint32(block[24:28], totalLen) // trailer
	buf.Write(block[:])
}

func writeIDB(t *testing.T, buf *bytes.Buffer, order binary.ByteOrder, iface ngTestIface) {
	t.Helper()
	body := make([]byte, 8) // linktype(2) + reserved(2) + snaplen(4)
	order.PutUint16(body[0:2], uint16(iface.linkType))
	order.PutUint32(body[4:8], 0) // snaplen = 0 (unlimited)

	if iface.tsResol != nil {
		// Add if_tsresol option.
		opt := make([]byte, 8)       // code(2) + len(2) + value(1) + pad(3)
		order.PutUint16(opt[0:2], 9) // if_tsresol
		order.PutUint16(opt[2:4], 1)
		opt[4] = *iface.tsResol
		body = append(body, opt...)

		// End of options.
		endOpt := make([]byte, 4)
		body = append(body, endOpt...)
	}

	totalLen := uint32(12 + len(body))
	var hdr [8]byte
	order.PutUint32(hdr[0:4], 0x00000001) // IDB
	order.PutUint32(hdr[4:8], totalLen)
	buf.Write(hdr[:])
	buf.Write(body)
	var trailer [4]byte
	order.PutUint32(trailer[:], totalLen)
	buf.Write(trailer[:])
}

func writeEPB(t *testing.T, buf *bytes.Buffer, order binary.ByteOrder, pkt ngTestPacket) {
	t.Helper()
	capLen := uint32(len(pkt.data))
	padLen := (4 - (capLen % 4)) % 4
	bodyLen := 20 + capLen + padLen
	totalLen := uint32(12 + bodyLen)

	var hdr [8]byte
	order.PutUint32(hdr[0:4], 0x00000006) // EPB
	order.PutUint32(hdr[4:8], totalLen)
	buf.Write(hdr[:])

	var epbHdr [20]byte
	order.PutUint32(epbHdr[0:4], pkt.ifaceID)
	// Timestamp: tsSec * 1000000 + tsUsec for microsecond resolution
	rawTS := uint64(pkt.tsSec)*1000000 + uint64(pkt.tsUsec)
	order.PutUint32(epbHdr[4:8], uint32(rawTS>>32))
	order.PutUint32(epbHdr[8:12], uint32(rawTS&0xFFFFFFFF))
	order.PutUint32(epbHdr[12:16], capLen)
	order.PutUint32(epbHdr[16:20], capLen) // origLen = capLen
	buf.Write(epbHdr[:])

	buf.Write(pkt.data)
	if padLen > 0 {
		buf.Write(make([]byte, padLen))
	}

	var trailer [4]byte
	order.PutUint32(trailer[:], totalLen)
	buf.Write(trailer[:])
}

func TestPcapNGBasic(t *testing.T) {
	tsResol6 := uint8(6) // microseconds (default)
	data := buildPcapNG(t, binary.LittleEndian,
		[]ngTestIface{{linkType: LinkEthernet, tsResol: &tsResol6}},
		[]ngTestPacket{{ifaceID: 0, tsSec: 1000, tsUsec: 500, data: []byte{0xAA, 0xBB}}},
	)

	rd, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if rd.Format() != FormatPcapNG {
		t.Errorf("format = %v, want pcapng", rd.Format())
	}

	pkt, err := rd.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if !bytes.Equal(pkt.Data, []byte{0xAA, 0xBB}) {
		t.Errorf("data = %x, want aabb", pkt.Data)
	}
	if pkt.LinkType != LinkEthernet {
		t.Errorf("linkType = %d, want %d", pkt.LinkType, LinkEthernet)
	}
}

func TestPcapNGTwoInterfaces(t *testing.T) {
	data := buildPcapNG(t, binary.LittleEndian,
		[]ngTestIface{
			{linkType: LinkEthernet, tsResol: nil},
			{linkType: LinkLinuxSLL, tsResol: nil},
		},
		[]ngTestPacket{
			{ifaceID: 0, tsSec: 100, tsUsec: 0, data: []byte{0x01}},
			{ifaceID: 1, tsSec: 101, tsUsec: 0, data: []byte{0x02}},
		},
	)

	rd, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	pkt1, err := rd.Next()
	if err != nil {
		t.Fatalf("Next 1: %v", err)
	}
	if pkt1.LinkType != LinkEthernet {
		t.Errorf("pkt1 linkType = %d, want Ethernet", pkt1.LinkType)
	}

	pkt2, err := rd.Next()
	if err != nil {
		t.Fatalf("Next 2: %v", err)
	}
	if pkt2.LinkType != LinkLinuxSLL {
		t.Errorf("pkt2 linkType = %d, want SLL", pkt2.LinkType)
	}
}

func TestPcapNGNanosResolution(t *testing.T) {
	// if_tsresol = 9 means 10^-9 (nanoseconds)
	tsResol := uint8(9)

	// Build manually since the helper uses microsecond formula.
	var buf bytes.Buffer
	writeSHB(t, &buf, binary.LittleEndian)
	writeIDB(t, &buf, binary.LittleEndian, ngTestIface{linkType: LinkEthernet, tsResol: &tsResol})

	// Write EPB with nanosecond timestamp
	pktData := []byte{0xAA}
	rawTS := uint64(1000)*1000000000 + uint64(123456789)
	capLen := uint32(len(pktData))
	padLen := (4 - (capLen % 4)) % 4
	bodyLen := 20 + capLen + padLen
	totalLen := uint32(12 + bodyLen)

	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0x00000006)
	binary.LittleEndian.PutUint32(hdr[4:8], totalLen)
	buf.Write(hdr[:])

	var epbHdr [20]byte
	binary.LittleEndian.PutUint32(epbHdr[0:4], 0) // ifaceID
	binary.LittleEndian.PutUint32(epbHdr[4:8], uint32(rawTS>>32))
	binary.LittleEndian.PutUint32(epbHdr[8:12], uint32(rawTS&0xFFFFFFFF))
	binary.LittleEndian.PutUint32(epbHdr[12:16], capLen)
	binary.LittleEndian.PutUint32(epbHdr[16:20], capLen)
	buf.Write(epbHdr[:])
	buf.Write(pktData)
	if padLen > 0 {
		buf.Write(make([]byte, padLen))
	}
	var trailer [4]byte
	binary.LittleEndian.PutUint32(trailer[:], totalLen)
	buf.Write(trailer[:])

	rd, err := Open(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	pkt, err := rd.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}

	expected := time.Unix(1000, 123456789)
	diff := pkt.Timestamp.Sub(expected)
	if diff < -time.Microsecond || diff > time.Microsecond {
		t.Errorf("timestamp = %v, want ~%v (diff %v)", pkt.Timestamp, expected, diff)
	}
}

func TestPcapNGBadTrailer(t *testing.T) {
	data := buildPcapNG(t, binary.LittleEndian,
		[]ngTestIface{{linkType: LinkEthernet}},
		[]ngTestPacket{{ifaceID: 0, tsSec: 100, data: []byte{0xAA}}},
	)

	// Corrupt the last 4 bytes (EPB trailer).
	copy(data[len(data)-4:], []byte{0xFF, 0xFF, 0xFF, 0xFF})

	rd, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	_, err = rd.Next()
	if err != ErrFormat {
		t.Errorf("Next = %v, want ErrFormat", err)
	}
}
