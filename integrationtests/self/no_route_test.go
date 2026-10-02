//go:build linux || darwin

package self_test

import (
	"context"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

// noRouteConn fails each write with errno while fail is set, as a host with no
// route to the peer does.
type noRouteConn struct {
	net.PacketConn
	errno  syscall.Errno
	fail   atomic.Bool
	failed atomic.Int32
}

func (c *noRouteConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.fail.Load() {
		c.failed.Add(1)
		return 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: os.NewSyscallError("sendto", c.errno)}
	}
	return c.PacketConn.WriteTo(b, addr)
}

// TestNoRouteSend sends stream data while the client has no route for a time.
// The connection stays open, and the data arrives when the route comes back.
func TestNoRouteSend(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN, syscall.EADDRNOTAVAIL} {
		t.Run(errno.Error(), func(t *testing.T) {
			server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
			require.NoError(t, err)
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c := &noRouteConn{PacketConn: newUDPConnLocalhost(t), errno: errno}
			conn, err := quic.Dial(ctx, c, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")
			serverConn, err := server.Accept(ctx)
			require.NoError(t, err)
			defer serverConn.CloseWithError(0, "")

			str, err := conn.OpenUniStream()
			require.NoError(t, err)
			c.fail.Store(true)
			// The write blocks while no packet goes out.
			written := make(chan error, 1)
			go func() {
				_, err := str.Write(PRData)
				if err == nil {
					err = str.Close()
				}
				written <- err
			}()
			require.Eventually(t, func() bool { return c.failed.Load() >= 10 }, 5*time.Second, time.Millisecond)
			time.Sleep(scaleDuration(100 * time.Millisecond))
			c.fail.Store(false)

			sstr, err := serverConn.AcceptUniStream(ctx)
			require.NoError(t, err)
			data, err := io.ReadAll(sstr)
			require.NoError(t, err)
			require.Equal(t, PRData, data)
			require.NoError(t, <-written)
			require.NoError(t, conn.Context().Err(), "client connection closed")
		})
	}
}
