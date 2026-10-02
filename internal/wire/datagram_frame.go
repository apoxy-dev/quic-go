package wire

import (
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// MaxDatagramSize is the max size of a DATAGRAM frame (RFC 9221) that fits into a 2 byte varint.
// It is a variable so that tests can change it.
var MaxDatagramSize protocol.ByteCount = 16383

// DatagramFrame carries one unreliable datagram (RFC 9221).
type DatagramFrame struct {
	DataLenPresent bool
	Data           []byte
}

// parseDatagramFrame parses a DATAGRAM frame into f. f.Data is a slice of b.
func parseDatagramFrame(f *DatagramFrame, b []byte, typ uint64, _ protocol.Version) (int, error) {
	startLen := len(b)
	f.DataLenPresent = typ&0x1 > 0

	var length uint64
	if f.DataLenPresent {
		var err error
		var l int
		length, l, err = quicvarint.Parse(b)
		if err != nil {
			return 0, replaceUnexpectedEOF(err)
		}
		b = b[l:]
		if length > uint64(len(b)) {
			return 0, io.EOF
		}
	} else {
		length = uint64(len(b))
	}
	f.Data = b[:length]
	return startLen - len(b) + int(length), nil
}

func (f *DatagramFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	typ := uint8(0x30)
	if f.DataLenPresent {
		typ ^= 0b1
	}
	b = append(b, typ)
	if f.DataLenPresent {
		b = quicvarint.Append(b, uint64(len(f.Data)))
	}
	b = append(b, f.Data...)
	return b, nil
}

// MaxDataLen returns the max data length of a frame that has maxSize bytes.
func (f *DatagramFrame) MaxDataLen(maxSize protocol.ByteCount, version protocol.Version) protocol.ByteCount {
	headerLen := protocol.ByteCount(1)
	if f.DataLenPresent {
		// Start with a 1 byte length. Below, remove 1 byte if the length needs 2 bytes.
		headerLen++
	}
	if headerLen > maxSize {
		return 0
	}
	maxDataLen := maxSize - headerLen
	if f.DataLenPresent && quicvarint.Len(uint64(maxDataLen)) != 1 {
		maxDataLen--
	}
	return maxDataLen
}

// Length returns the number of bytes of the encoded frame.
func (f *DatagramFrame) Length(_ protocol.Version) protocol.ByteCount {
	length := 1 + protocol.ByteCount(len(f.Data))
	if f.DataLenPresent {
		length += protocol.ByteCount(quicvarint.Len(uint64(len(f.Data))))
	}
	return length
}
