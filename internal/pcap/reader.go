// Package pcap provides a streaming reader for classic pcap and pcapng capture files.
//
// It supports all four classic pcap byte-order and timestamp-resolution magics,
// pcapng with per-interface link types and timestamp resolution, and produces
// a uniform stream of [Packet] records.
//
// Design: streaming only, no seeking. Memory bounded by one packet at a time.
// Truncated files yield [ErrTruncated] but keep earlier packets. Format errors
// yield [ErrFormat].
package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// Errors returned by the reader.
var (
	// ErrFormat indicates the file is not a valid pcap or pcapng.
	ErrFormat = errors.New("pcap: unrecognised format")

	// ErrTruncated indicates the file was truncated mid-record.
	// Earlier packets are still available.
	ErrTruncated = errors.New("pcap: file truncated mid-record")
)

// Format identifies the capture file format.
type Format int

const (
	FormatClassicPcap Format = iota
	FormatPcapNG
)

func (f Format) String() string {
	switch f {
	case FormatClassicPcap:
		return "pcap"
	case FormatPcapNG:
		return "pcapng"
	default:
		return "unknown"
	}
}

// LinkType is a pcap link-layer header type.
type LinkType uint32

// Common link types we support.
const (
	LinkNull       LinkType = 0
	LinkEthernet   LinkType = 1
	LinkRawIPv4    LinkType = 12
	LinkRawIPv6    LinkType = 14
	LinkLinuxSLL   LinkType = 113
	LinkRawIP      LinkType = 101
	LinkBSDLoop    LinkType = 108
	LinkLinuxSLL2  LinkType = 276
	LinkRawIPv4DLT LinkType = 228
	LinkRawIPv6DLT LinkType = 229
)

// Packet is a single captured packet.
type Packet struct {
	// Index is the 0-based packet number in the file.
	Index int
	// Timestamp of capture.
	Timestamp time.Time
	// Data is the raw packet bytes (may be shorter than OrigLen).
	Data []byte
	// CaptureLen is the number of bytes actually captured.
	CaptureLen uint32
	// OrigLen is the original packet length on the wire.
	OrigLen uint32
	// LinkType for this packet (may vary per interface in pcapng).
	LinkType LinkType
}

// maxRecordLen is the maximum per-record allocation (16 MiB).
const maxRecordLen = 16 * 1024 * 1024

// Classic pcap magic numbers.
const (
	magicMicrosLE uint32 = 0xa1b2c3d4
	magicMicrosBE uint32 = 0xd4c3b2a1
	magicNanosLE  uint32 = 0xa1b23c4d
	magicNanosBE  uint32 = 0x4d3cb2a1
)

// pcapng magic (Section Header Block type).
const pcapngSHBType uint32 = 0x0a0d0d0a

// Reader reads packets from a pcap or pcapng file.
type Reader struct {
	r      io.Reader
	format Format
	index  int
	err    error
	buf    []byte // reusable read buffer

	// classic pcap state
	classicOrder binary.ByteOrder
	classicNanos bool
	classicLink  LinkType

	// pcapng state
	ngOrder      binary.ByteOrder
	ngInterfaces []ngInterface
}

type ngInterface struct {
	linkType LinkType
	tsResol  uint8 // timestamp resolution exponent
	tsIsPow2 bool  // true = 2^-tsResol, false = 10^-tsResol
}

// Open creates a new Reader from an io.Reader. It reads the file header
// to determine the format. Returns [ErrFormat] if the input is not a
// recognized capture format.
func Open(r io.Reader) (*Reader, error) {
	rd := &Reader{r: r, buf: make([]byte, 0, 65536)}

	// Read the first 4 bytes to determine format.
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return nil, ErrFormat
		}
		return nil, fmt.Errorf("pcap: reading magic: %w", err)
	}

	m := binary.LittleEndian.Uint32(magic[:])
	switch m {
	case magicMicrosLE:
		return rd.initClassic(magic[:], binary.LittleEndian, false)
	case magicMicrosBE:
		return rd.initClassic(magic[:], binary.BigEndian, false)
	case magicNanosLE:
		return rd.initClassic(magic[:], binary.LittleEndian, true)
	case magicNanosBE:
		return rd.initClassic(magic[:], binary.BigEndian, true)
	case pcapngSHBType:
		return rd.initPcapNG(magic[:])
	default:
		return nil, ErrFormat
	}
}

func (rd *Reader) initClassic(magic []byte, order binary.ByteOrder, nanos bool) (*Reader, error) {
	rd.format = FormatClassicPcap
	rd.classicOrder = order
	rd.classicNanos = nanos

	// Read remaining 20 bytes of global header (24 total - 4 magic).
	var hdr [20]byte
	if _, err := io.ReadFull(rd.r, hdr[:]); err != nil {
		return nil, fmt.Errorf("pcap: reading header: %w", err)
	}

	// Bytes 16-19 (offset 16 in full header, 12 in remaining) = link type.
	// Full header layout: magic(4) major(2) minor(2) thiszone(4) sigfigs(4) snaplen(4) linktype(4)
	lt := order.Uint32(hdr[16:20])
	// Low 28 bits per pcap spec (FCS bits in high nibble).
	rd.classicLink = LinkType(lt & 0x0FFFFFFF)

	return rd, nil
}

func (rd *Reader) initPcapNG(magic []byte) (*Reader, error) {
	rd.format = FormatPcapNG

	// We have the block type (0x0a0d0d0a). Read the rest of the SHB.
	// Block Total Length (4 bytes).
	var btl [4]byte
	if _, err := io.ReadFull(rd.r, btl[:]); err != nil {
		return nil, fmt.Errorf("pcapng: reading SHB length: %w", err)
	}

	// Byte-Order Magic (4 bytes) tells us the endianness.
	var bom [4]byte
	if _, err := io.ReadFull(rd.r, bom[:]); err != nil {
		return nil, fmt.Errorf("pcapng: reading byte-order magic: %w", err)
	}

	bomVal := binary.LittleEndian.Uint32(bom[:])
	switch bomVal {
	case 0x1A2B3C4D:
		rd.ngOrder = binary.LittleEndian
	case 0x4D3C2B1A:
		rd.ngOrder = binary.BigEndian
	default:
		return nil, ErrFormat
	}

	totalLen := rd.ngOrder.Uint32(btl[:])
	if totalLen < 28 { // minimum SHB size
		return nil, ErrFormat
	}

	// Skip rest of SHB body (we already read 12 bytes: type + btl + bom).
	// Remaining = totalLen - 12. But we also need to skip the trailer (4 bytes).
	remaining := int64(totalLen) - 12
	if remaining > maxRecordLen {
		return nil, ErrFormat
	}
	if _, err := io.CopyN(io.Discard, rd.r, remaining); err != nil {
		return nil, fmt.Errorf("pcapng: skipping SHB body: %w", err)
	}

	return rd, nil
}

// Format returns the detected file format.
func (rd *Reader) Format() Format {
	return rd.format
}

// Next reads the next packet. Returns io.EOF when no more packets are available.
// Returns [ErrTruncated] if the file was cut short mid-record.
func (rd *Reader) Next() (Packet, error) {
	if rd.err != nil {
		return Packet{}, rd.err
	}

	switch rd.format {
	case FormatClassicPcap:
		return rd.nextClassic()
	case FormatPcapNG:
		return rd.nextPcapNG()
	default:
		return Packet{}, ErrFormat
	}
}

func (rd *Reader) nextClassic() (Packet, error) {
	// Record header: 16 bytes.
	var hdr [16]byte
	_, err := io.ReadFull(rd.r, hdr[:])
	if err != nil {
		if errors.Is(err, io.EOF) {
			rd.err = io.EOF
			return Packet{}, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			rd.err = ErrTruncated
			return Packet{}, ErrTruncated
		}
		rd.err = err
		return Packet{}, err
	}

	order := rd.classicOrder
	tsSec := order.Uint32(hdr[0:4])
	tsFrac := order.Uint32(hdr[4:8])
	capLen := order.Uint32(hdr[8:12])
	origLen := order.Uint32(hdr[12:16])

	if capLen > maxRecordLen {
		rd.err = ErrFormat
		return Packet{}, ErrFormat
	}

	var ts time.Time
	if rd.classicNanos {
		ts = time.Unix(int64(tsSec), int64(tsFrac))
	} else {
		ts = time.Unix(int64(tsSec), int64(tsFrac)*1000)
	}

	data := rd.getBuf(int(capLen))
	_, err = io.ReadFull(rd.r, data)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			rd.err = ErrTruncated
			return Packet{}, ErrTruncated
		}
		rd.err = err
		return Packet{}, err
	}

	pkt := Packet{
		Index:      rd.index,
		Timestamp:  ts,
		Data:       data,
		CaptureLen: capLen,
		OrigLen:    origLen,
		LinkType:   rd.classicLink,
	}
	rd.index++
	return pkt, nil
}

func (rd *Reader) nextPcapNG() (Packet, error) {
	for {
		// Read block type and total length (8 bytes).
		var blockHdr [8]byte
		_, err := io.ReadFull(rd.r, blockHdr[:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				rd.err = io.EOF
				return Packet{}, io.EOF
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				rd.err = ErrTruncated
				return Packet{}, ErrTruncated
			}
			rd.err = err
			return Packet{}, err
		}

		order := rd.ngOrder
		blockType := order.Uint32(blockHdr[0:4])
		totalLen := order.Uint32(blockHdr[4:8])

		if totalLen < 12 { // minimum: type(4) + length(4) + trailer(4)
			rd.err = ErrFormat
			return Packet{}, ErrFormat
		}

		bodyLen := totalLen - 12 // subtract type, length, trailer

		switch blockType {
		case 0x0a0d0d0a: // Section Header Block — new section
			if err := rd.parseSHB(bodyLen); err != nil {
				return Packet{}, err
			}
		case 0x00000001: // Interface Description Block
			if err := rd.parseIDB(bodyLen); err != nil {
				return Packet{}, err
			}
		case 0x00000006: // Enhanced Packet Block
			pkt, err := rd.parseEPB(bodyLen)
			if err != nil {
				return Packet{}, err
			}
			return pkt, nil
		case 0x00000003: // Simple Packet Block
			pkt, err := rd.parseSPB(bodyLen)
			if err != nil {
				return Packet{}, err
			}
			return pkt, nil
		default:
			// Skip unknown block types.
			if err := rd.skipAndCheckTrailer(bodyLen, totalLen); err != nil {
				return Packet{}, err
			}
		}
	}
}

func (rd *Reader) parseSHB(bodyLen uint32) error {
	if bodyLen > maxRecordLen {
		rd.err = ErrFormat
		return ErrFormat
	}

	data := rd.getBuf(int(bodyLen))
	if _, err := io.ReadFull(rd.r, data); err != nil {
		rd.err = mapReadErr(err)
		return rd.err
	}

	// Byte-Order Magic is the first 4 bytes of the body.
	if len(data) < 4 {
		rd.err = ErrFormat
		return ErrFormat
	}
	bomVal := binary.LittleEndian.Uint32(data[0:4])
	switch bomVal {
	case 0x1A2B3C4D:
		rd.ngOrder = binary.LittleEndian
	case 0x4D3C2B1A:
		rd.ngOrder = binary.BigEndian
	default:
		rd.err = ErrFormat
		return ErrFormat
	}

	// Reset interfaces for the new section.
	rd.ngInterfaces = rd.ngInterfaces[:0]

	// Read trailer.
	return rd.readTrailer(bodyLen + 12) // +12 for type+length+trailer
}

func (rd *Reader) parseIDB(bodyLen uint32) error {
	if bodyLen < 8 { // linktype(2) + reserved(2) + snaplen(4)
		rd.err = ErrFormat
		return ErrFormat
	}
	if bodyLen > maxRecordLen {
		rd.err = ErrFormat
		return ErrFormat
	}

	data := rd.getBuf(int(bodyLen))
	if _, err := io.ReadFull(rd.r, data); err != nil {
		rd.err = mapReadErr(err)
		return rd.err
	}

	order := rd.ngOrder
	lt := LinkType(order.Uint16(data[0:2]))
	// data[2:4] reserved
	// data[4:8] snaplen (not used here)

	iface := ngInterface{
		linkType: lt,
		tsResol:  6, // default: microseconds (10^-6)
		tsIsPow2: false,
	}

	// Parse options starting at offset 8.
	opts := data[8:]
	for len(opts) >= 4 {
		optCode := order.Uint16(opts[0:2])
		optLen := order.Uint16(opts[2:4])

		if optCode == 0 { // opt_endofopt
			break
		}

		padLen := (4 - (optLen % 4)) % 4
		totalOptLen := int(4) + int(optLen) + int(padLen)

		if len(opts) < totalOptLen {
			break
		}

		if optCode == 9 && optLen >= 1 { // if_tsresol
			val := opts[4]
			if val&0x80 != 0 {
				iface.tsIsPow2 = true
				iface.tsResol = val & 0x7F
			} else {
				iface.tsIsPow2 = false
				iface.tsResol = val
			}
		}

		opts = opts[totalOptLen:]
	}

	rd.ngInterfaces = append(rd.ngInterfaces, iface)

	return rd.readTrailer(bodyLen + 12)
}

func (rd *Reader) parseEPB(bodyLen uint32) (Packet, error) {
	if bodyLen < 20 { // interfaceID(4)+tsHigh(4)+tsLow(4)+capLen(4)+origLen(4)
		rd.err = ErrFormat
		return Packet{}, ErrFormat
	}
	if bodyLen > maxRecordLen {
		rd.err = ErrFormat
		return Packet{}, ErrFormat
	}

	data := rd.getBuf(int(bodyLen))
	if _, err := io.ReadFull(rd.r, data); err != nil {
		rd.err = mapReadErr(err)
		return Packet{}, rd.err
	}

	order := rd.ngOrder
	ifaceID := order.Uint32(data[0:4])
	tsHigh := order.Uint32(data[4:8])
	tsLow := order.Uint32(data[8:12])
	capLen := order.Uint32(data[12:16])
	origLen := order.Uint32(data[16:20])

	if int(ifaceID) >= len(rd.ngInterfaces) {
		rd.err = ErrFormat
		return Packet{}, ErrFormat
	}

	iface := rd.ngInterfaces[ifaceID]
	ts := rd.resolveTimestamp(tsHigh, tsLow, iface)

	// Packet data starts at offset 20.
	padCapLen := capLen + (4-(capLen%4))%4
	if 20+padCapLen > bodyLen {
		rd.err = ErrFormat
		return Packet{}, ErrFormat
	}

	pktData := make([]byte, capLen)
	copy(pktData, data[20:20+capLen])

	pkt := Packet{
		Index:      rd.index,
		Timestamp:  ts,
		Data:       pktData,
		CaptureLen: capLen,
		OrigLen:    origLen,
		LinkType:   iface.linkType,
	}
	rd.index++

	if err := rd.readTrailer(bodyLen + 12); err != nil {
		return Packet{}, err
	}

	return pkt, nil
}

func (rd *Reader) parseSPB(bodyLen uint32) (Packet, error) {
	if bodyLen < 4 { // origLen(4)
		rd.err = ErrFormat
		return Packet{}, ErrFormat
	}
	if bodyLen > maxRecordLen {
		rd.err = ErrFormat
		return Packet{}, ErrFormat
	}

	data := rd.getBuf(int(bodyLen))
	if _, err := io.ReadFull(rd.r, data); err != nil {
		rd.err = mapReadErr(err)
		return Packet{}, rd.err
	}

	order := rd.ngOrder
	origLen := order.Uint32(data[0:4])
	capLen := bodyLen - 4 // rest is packet data

	// SPB uses interface 0.
	if len(rd.ngInterfaces) == 0 {
		rd.err = ErrFormat
		return Packet{}, ErrFormat
	}

	pktData := make([]byte, capLen)
	copy(pktData, data[4:4+capLen])

	pkt := Packet{
		Index:      rd.index,
		Timestamp:  time.Time{}, // SPB has no timestamp
		Data:       pktData,
		CaptureLen: capLen,
		OrigLen:    origLen,
		LinkType:   rd.ngInterfaces[0].linkType,
	}
	rd.index++

	if err := rd.readTrailer(bodyLen + 12); err != nil {
		return Packet{}, err
	}

	return pkt, nil
}

func (rd *Reader) resolveTimestamp(high, low uint32, iface ngInterface) time.Time {
	rawTS := (uint64(high) << 32) | uint64(low)

	var divisor float64
	if iface.tsIsPow2 {
		divisor = math.Pow(2, float64(iface.tsResol))
	} else {
		divisor = math.Pow(10, float64(iface.tsResol))
	}

	seconds := float64(rawTS) / divisor
	sec := int64(seconds)
	nsec := int64((seconds - float64(sec)) * 1e9)
	return time.Unix(sec, nsec)
}

func (rd *Reader) readTrailer(expectedTotalLen uint32) error {
	var trailer [4]byte
	if _, err := io.ReadFull(rd.r, trailer[:]); err != nil {
		rd.err = mapReadErr(err)
		return rd.err
	}
	trailerLen := rd.ngOrder.Uint32(trailer[:])
	if trailerLen != expectedTotalLen {
		rd.err = ErrFormat
		return ErrFormat
	}
	return nil
}

func (rd *Reader) skipAndCheckTrailer(bodyLen, totalLen uint32) error {
	if bodyLen > maxRecordLen {
		rd.err = ErrFormat
		return ErrFormat
	}
	if _, err := io.CopyN(io.Discard, rd.r, int64(bodyLen)); err != nil {
		rd.err = mapReadErr(err)
		return rd.err
	}
	return rd.readTrailer(totalLen)
}

func (rd *Reader) getBuf(n int) []byte {
	if cap(rd.buf) >= n {
		return rd.buf[:n]
	}
	rd.buf = make([]byte, n)
	return rd.buf
}

func mapReadErr(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return ErrTruncated
	}
	return err
}
