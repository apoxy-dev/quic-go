package wire

import (
	"io"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseDatagramFrameWithLength(t *testing.T) {
	data := encodeVarInt(0x6) // length
	data = append(data, []byte("foobar")...)
	var frame DatagramFrame
	l, err := parseDatagramFrame(&frame, data, 0x30^0x1, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), frame.Data)
	require.True(t, frame.DataLenPresent)
	require.Equal(t, len(data), l)
}

func TestParseDatagramFrameWithoutLength(t *testing.T) {
	data := []byte("Lorem ipsum dolor sit amet")
	var frame DatagramFrame
	l, err := parseDatagramFrame(&frame, data, 0x30, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, []byte("Lorem ipsum dolor sit amet"), frame.Data)
	require.False(t, frame.DataLenPresent)
	require.Equal(t, len(data), l)
}

func TestParseDatagramFrameErrorsOnLengthLongerThanFrame(t *testing.T) {
	data := encodeVarInt(0x6) // length
	data = append(data, []byte("fooba")...)
	_, err := parseDatagramFrame(&DatagramFrame{}, data, 0x30^0x1, protocol.Version1)
	require.Equal(t, io.EOF, err)
}

func TestParseDatagramFrameErrorsOnEOFs(t *testing.T) {
	const typ = 0x30 ^ 0x1
	data := encodeVarInt(6) // length
	data = append(data, []byte("foobar")...)
	l, err := parseDatagramFrame(&DatagramFrame{}, data, typ, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, err = parseDatagramFrame(&DatagramFrame{}, data[0:i], typ, protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWriteDatagramFrameWithLength(t *testing.T) {
	f := &DatagramFrame{
		DataLenPresent: true,
		Data:           []byte("foobar"),
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x30 ^ 0x1}
	expected = append(expected, encodeVarInt(0x6)...)
	expected = append(expected, []byte("foobar")...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(f.Length(protocol.Version1)))
}

func TestWriteDatagramFrameWithoutLength(t *testing.T) {
	f := &DatagramFrame{Data: []byte("Lorem ipsum")}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x30}
	expected = append(expected, []byte("Lorem ipsum")...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(f.Length(protocol.Version1)))
}

func TestMaxDatagramLenWithoutDataLenPresent(t *testing.T) {
	const maxSize = 3000
	data := make([]byte, maxSize)
	f := &DatagramFrame{}
	for i := 1; i < 3000; i++ {
		f.Data = nil
		maxDataLen := f.MaxDataLen(protocol.ByteCount(i), protocol.Version1)
		if maxDataLen == 0 { // 0 means that no valid DATAGRAM frame can be written
			// check that writing a minimal size DATAGRAM frame (i.e. with 1 byte data) is actually larger than the desired size
			f.Data = []byte{0}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)
			require.Greater(t, len(b), i)
			continue
		}
		f.Data = data[:int(maxDataLen)]
		b, err := f.Append(nil, protocol.Version1)
		require.NoError(t, err)
		require.Len(t, b, i)
	}
}

func TestMaxDatagramLenWithDataLenPresent(t *testing.T) {
	const maxSize = 3000
	data := make([]byte, maxSize)
	f := &DatagramFrame{DataLenPresent: true}
	var frameOneByteTooSmallCounter int
	for i := 1; i < 3000; i++ {
		f.Data = nil
		maxDataLen := f.MaxDataLen(protocol.ByteCount(i), protocol.Version1)
		if maxDataLen == 0 { // 0 means that no valid DATAGRAM frame can be written
			// check that writing a minimal size DATAGRAM frame (i.e. with 1 byte data) is actually larger than the desired size
			f.Data = []byte{0}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)
			require.Greater(t, len(b), i)
			continue
		}
		f.Data = data[:int(maxDataLen)]
		b, err := f.Append(nil, protocol.Version1)
		require.NoError(t, err)
		// There's *one* pathological case, where a data length of x can be encoded into 1 byte
		// but a data lengths of x+1 needs 2 bytes
		// In that case, it's impossible to create a DATAGRAM frame of the desired size
		if len(b) == i-1 {
			frameOneByteTooSmallCounter++
			continue
		}
		require.Len(t, b, i)
	}
	require.Equal(t, 1, frameOneByteTooSmallCounter)
}

func BenchmarkParseDatagramFrame(b *testing.B) {
	f := &DatagramFrame{DataLenPresent: true, Data: make([]byte, 1350)}
	data, err := f.Append(nil, protocol.Version1)
	if err != nil {
		b.Fatal(err)
	}
	parser := NewFrameParser(true, false)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, frame, err := parser.ParseNext(data, protocol.Encryption1RTT, protocol.Version1)
		if err != nil {
			b.Fatal(err)
		}
		if len(frame.(*DatagramFrame).Data) != len(f.Data) {
			b.Fatal("wrong datagram length")
		}
	}
}
