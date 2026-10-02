//go:build linux || darwin

package quic

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/sys/unix"
)

// TestSendQueueSendErrors checks which send errors the queue keeps sending after.
func TestSendQueueSendErrors(t *testing.T) {
	cases := []struct {
		errno syscall.Errno
		keep  bool // The queue sends the next packet.
	}{
		{unix.ENETUNREACH, true},
		{unix.EHOSTUNREACH, true},
		{unix.ENETDOWN, true},
		{unix.EADDRNOTAVAIL, true},
		{unix.EMSGSIZE, true},
		{unix.ECONNREFUSED, false},
	}
	for _, tc := range cases {
		t.Run(tc.errno.Error(), func(t *testing.T) {
			c := NewMockSendConn(gomock.NewController(t))
			q := newSendQueue(c)
			sendErr := &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendmsg", tc.errno)}
			c.EXPECT().Write([]byte("first"), gomock.Any(), gomock.Any()).Return(sendErr)
			written := make(chan struct{})
			if tc.keep {
				c.EXPECT().Write([]byte("second"), gomock.Any(), gomock.Any()).Do(
					func([]byte, uint16, protocol.ECN) error { close(written); return nil },
				)
			}
			errChan := make(chan error, 1)
			go func() { errChan <- q.Run() }()
			q.Send(getPacketWithContents([]byte("first")), 0, protocol.ECNNon)
			q.Send(getPacketWithContents([]byte("second")), 0, protocol.ECNNon)

			if !tc.keep {
				select {
				case err := <-errChan:
					require.ErrorIs(t, err, tc.errno)
				case <-time.After(time.Second):
					t.Fatal("timeout")
				}
				return
			}
			select {
			case <-written:
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}
			q.Close()
			require.NoError(t, <-errChan)
		})
	}
}
