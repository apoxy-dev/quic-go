package self_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

func runMultiplexTestServer(t *testing.T, ln *quic.Listener) {
	t.Helper()
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		str, err := conn.OpenUniStream()
		require.NoError(t, err)
		go func() {
			defer str.Close()
			_, err = str.Write(PRData)
			require.NoError(t, err)
		}()

		t.Cleanup(func() { conn.CloseWithError(0, "") })
	}
}

func dialAndReceiveData(tr *quic.Transport, addr net.Addr) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, addr, getTLSClientConfig(), getQuicConfig(nil))
	if err != nil {
		return fmt.Errorf("error dialing: %w", err)
	}
	str, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return fmt.Errorf("error accepting stream: %w", err)
	}
	data, err := io.ReadAll(str)
	if err != nil {
		return fmt.Errorf("error reading data: %w", err)
	}
	if !bytes.Equal(data, PRData) {
		return fmt.Errorf("data mismatch: got %q, expected %q", data, PRData)
	}
	return nil
}

func TestMultiplexesConnectionsToSameServer(t *testing.T) {
	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()
	go runMultiplexTestServer(t, server)

	tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	addTracer(tr)
	defer tr.Close()

	errChan1 := make(chan error, 1)
	go func() { errChan1 <- dialAndReceiveData(tr, server.Addr()) }()
	errChan2 := make(chan error, 1)
	go func() { errChan2 <- dialAndReceiveData(tr, server.Addr()) }()

	select {
	case err := <-errChan1:
		require.NoError(t, err, "error dialing server 1")
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for done1 to close")
	}
	select {
	case err := <-errChan2:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for done2 to close")
	}
}

func TestMultiplexingToDifferentServers(t *testing.T) {
	server1, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server1.Close()
	go runMultiplexTestServer(t, server1)

	server2, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server2.Close()
	go runMultiplexTestServer(t, server2)

	tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	addTracer(tr)
	defer tr.Close()

	errChan1 := make(chan error, 1)
	go func() { errChan1 <- dialAndReceiveData(tr, server1.Addr()) }()
	errChan2 := make(chan error, 1)
	go func() { errChan2 <- dialAndReceiveData(tr, server2.Addr()) }()

	select {
	case err := <-errChan1:
		require.NoError(t, err, "error dialing server 1")
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for done1 to close")
	}
	select {
	case err := <-errChan2:
		require.NoError(t, err, "error dialing server 2")
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for done2 to close")
	}
}

func TestMultiplexingConnectToSelf(t *testing.T) {
	tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	addTracer(tr)
	defer tr.Close()

	server, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()
	go runMultiplexTestServer(t, server)

	errChan := make(chan error, 1)
	go func() { errChan <- dialAndReceiveData(tr, server.Addr()) }()

	select {
	case err := <-errChan:
		require.NoError(t, err, "error dialing server")
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for connection to close")
	}
}

func TestMultiplexingServerAndClientOnSameConn(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("This test requires setting of iptables rules on Linux, see https://stackoverflow.com/questions/23859164/linux-udp-socket-sendto-operation-not-permitted.")
	}

	tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	addTracer(tr1)
	defer tr1.Close()
	server1, err := tr1.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server1.Close()

	tr2 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	addTracer(tr2)
	defer tr2.Close()
	server2, err := tr2.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server2.Close()

	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		dialAndReceiveData(tr2, server1.Addr())
	}()

	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		dialAndReceiveData(tr1, server2.Addr())
	}()

	select {
	case <-done1:
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for done1 to close")
	}
	select {
	case <-done2:
	case <-time.After(time.Second):
		t.Error("timeout waiting for done2 to close")
	}
}

func TestMultiplexingNonQUICPackets(t *testing.T) {
	const numPackets = 100

	tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	addTracer(tr1)
	server, err := tr1.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	tr2 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr2.Close()
	addTracer(tr2)

	type nonQUICPacket struct {
		b    []byte
		addr net.Addr
		err  error
	}
	rcvdPackets := make(chan nonQUICPacket, numPackets)
	receiveCtx, receiveCancel := context.WithCancel(context.Background())
	defer receiveCancel()
	// start receiving non-QUIC packets
	go func() {
		for {
			b := make([]byte, 1024)
			n, addr, err := tr2.ReadNonQUICPacket(receiveCtx, b)
			if errors.Is(err, context.Canceled) {
				return
			}
			rcvdPackets <- nonQUICPacket{b: b[:n], addr: addr, err: err}
		}
	}()

	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	conn, err := tr2.Dial(ctx2, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx2)
	require.NoError(t, err)
	serverStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)

	// send a non-QUIC packet every 100µs
	const packetLen = 128
	errChanNonQUIC := make(chan error, 1)
	sendNonQUICPacket := make(chan struct{}, 1)
	go func() {
		var seed [32]byte
		rand.Read(seed[:])
		random := mrand.NewChaCha8(seed)
		defer close(errChanNonQUIC)
		var sentPackets int
		for range sendNonQUICPacket {
			b := make([]byte, packetLen)
			random.Read(b[1:]) // keep the first byte set to 0, so it's not classified as a QUIC packet
			_, err := tr1.WriteTo(b, tr2.Conn.LocalAddr())
			// The first sendmsg call on a new UDP socket sometimes errors on Linux.
			// It's not clear why this happens.
			// See https://github.com/golang/go/issues/63322.
			if err != nil && sentPackets == 0 && runtime.GOOS == "linux" && isPermissionError(err) {
				_, err = tr1.WriteTo(b, tr2.Conn.LocalAddr())
			}
			if err != nil {
				errChanNonQUIC <- err
				return
			}
			sentPackets++
		}
	}()

	sendQUICPacket := make(chan struct{}, 1)
	errChanQUIC := make(chan error, 1)
	var dataSent []byte
	go func() {
		defer close(errChanQUIC)
		defer serverStr.Close()

		var seed [32]byte
		rand.Read(seed[:])
		random := mrand.NewChaCha8(seed)
		for range sendQUICPacket {
			b := make([]byte, 1024)
			random.Read(b)
			if _, err := serverStr.Write(b); err != nil {
				errChanQUIC <- err
				return
			}
			dataSent = append(dataSent, b...)
		}
	}()

	dataChan := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		str, err := conn.AcceptUniStream(ctx2)
		if err != nil {
			readErr <- err
			return
		}
		data, err := io.ReadAll(str)
		if err != nil {
			readErr <- err
			return
		}
		dataChan <- data
	}()

	ticker := time.NewTicker(scaleDuration(200 * time.Microsecond))
	defer ticker.Stop()
	for range numPackets {
		sendNonQUICPacket <- struct{}{}
		sendQUICPacket <- struct{}{}
		<-ticker.C
	}
	close(sendNonQUICPacket)
	close(sendQUICPacket)

	select {
	case err := <-errChanNonQUIC:
		require.NoError(t, err, "error sending non-QUIC packets")
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for non-QUIC packets to be sent")
	}
	select {
	case err := <-errChanQUIC:
		require.NoError(t, err, "error sending QUIC packets")
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for QUIC packets to be sent")
	}
	select {
	case err := <-readErr:
		require.NoError(t, err, "error reading stream data")
	case dataRcvd := <-dataChan:
		require.Equal(t, dataSent, dataRcvd, "stream data mismatch")
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for stream data to be read")
	}

	// make sure we don't overflow the capacity of the channel
	require.LessOrEqual(t, numPackets, cap(rcvdPackets), "too many non-QUIC packets sent: %d > %d", numPackets, cap(rcvdPackets))

	// now receive these packets
	minExpected := numPackets * 4 / 5
	timeout := time.After(time.Second)
	var counter int
	for counter < minExpected {
		select {
		case p := <-rcvdPackets:
			require.Equal(t, tr1.Conn.LocalAddr(), p.addr, "non-QUIC packet received from wrong address")
			require.Equal(t, packetLen, len(p.b), "non-QUIC packet incorrect length")
			require.NoError(t, p.err, "error receiving non-QUIC packet")
			counter++
		case <-timeout:
			t.Fatalf("didn't receive enough non-QUIC packets: %d < %d", counter, minExpected)
		}
	}
}

// NonQUICPacketHandler gets every packet of a burst, and QUIC on the same Transport still works.
func TestMultiplexingNonQUICPacketHandler(t *testing.T) {
	const numPackets = 10000
	const packetLen = 128
	// 8x the ReadNonQUICPacket queue. Wait after each burst so the kernel buffer does not drop.
	const burst = 256

	tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	addTracer(tr1)
	server, err := tr1.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	var mx sync.Mutex
	seen := make([]bool, numPackets)
	var received int
	var handlerErr error
	receivedAll := func(n int) func() bool {
		return func() bool {
			mx.Lock()
			defer mx.Unlock()
			return handlerErr != nil || received == n
		}
	}
	tr2 := &quic.Transport{
		Conn: newUDPConnLocalhost(t),
		NonQUICPacketHandler: func(b []byte, addr net.Addr) {
			mx.Lock()
			defer mx.Unlock()
			if handlerErr != nil {
				return
			}
			if len(b) != packetLen || addr.String() != tr1.Conn.LocalAddr().String() {
				handlerErr = fmt.Errorf("unexpected packet: %d bytes from %s", len(b), addr)
				return
			}
			i := binary.BigEndian.Uint32(b[1:])
			if i >= numPackets || seen[i] || !bytes.Equal(b[5:], bytes.Repeat([]byte{byte(i)}, packetLen-5)) {
				handlerErr = fmt.Errorf("unexpected or duplicate packet %d", i)
				return
			}
			seen[i] = true
			received++
		},
	}
	defer tr2.Close()
	addTracer(tr2)

	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Second))
	defer cancel()
	conn, err := tr2.Dial(ctx, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)

	// The server echoes the stream data back to the client.
	go func() {
		str, err := serverConn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		io.Copy(str, str)
		str.Close()
	}()
	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	require.NoError(t, str.SetDeadline(time.Now().Add(scaleDuration(10*time.Second))))
	echo := func(i int) {
		msg := make([]byte, 1024)
		rand.Read(msg)
		_, err := str.Write(msg)
		require.NoError(t, err)
		rcvd := make([]byte, len(msg))
		_, err = io.ReadFull(str, rcvd)
		require.NoError(t, err, "echo after %d packets", i)
		require.Equal(t, msg, rcvd)
	}

	for i := range numPackets {
		b := make([]byte, packetLen) // keep the first byte set to 0, so it's not classified as a QUIC packet
		binary.BigEndian.PutUint32(b[1:], uint32(i))
		copy(b[5:], bytes.Repeat([]byte{byte(i)}, packetLen-5))
		_, err := tr1.WriteTo(b, tr2.Conn.LocalAddr())
		// The first sendmsg call on a new UDP socket sometimes errors on Linux.
		// See https://github.com/golang/go/issues/63322.
		if err != nil && i == 0 && runtime.GOOS == "linux" && isPermissionError(err) {
			_, err = tr1.WriteTo(b, tr2.Conn.LocalAddr())
		}
		require.NoError(t, err)
		if (i+1)%burst == 0 || i+1 == numPackets {
			require.Eventually(t, receivedAll(i+1), scaleDuration(5*time.Second), scaleDuration(time.Millisecond))
			echo(i + 1)
		}
	}

	mx.Lock()
	defer mx.Unlock()
	require.NoError(t, handlerErr)
	require.Equal(t, numPackets, received)
}
