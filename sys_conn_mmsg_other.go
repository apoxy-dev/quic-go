//go:build darwin || freebsd || (linux && !amd64 && !arm64)

package quic

import (
	"net"
	"syscall"
)

// newMmsgConn returns nil, and the conn reads with x/net.
func newMmsgConn(syscall.RawConn, net.Addr) batchConn { return nil }
