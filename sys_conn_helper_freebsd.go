//go:build freebsd

package quic

import (
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	msgTypeIPTOS = unix.IP_RECVTOS
	ipv4PKTINFO  = 0x7
	// The kernel has no UDP GRO, so no control message has this type.
	msgTypeUDPGRO = -1
)

const ecnIPv4DataLen = 1

const batchSize = 8

// groBatchSize is not used: the kernel has no UDP GRO.
const groBatchSize = batchSize

func parseIPv4PktInfo(body []byte) (ip netip.Addr, _ uint32, ok bool) {
	// struct in_pktinfo {
	// 	struct in_addr ipi_addr;     /* Header Destination address */
	// };
	if len(body) != 4 {
		return netip.Addr{}, 0, false
	}
	return netip.AddrFrom4(*(*[4]byte)(body)), 0, true
}

func isGSOEnabled(syscall.RawConn) bool { return false }

func isGROEnabled(syscall.RawConn) bool { return false }

func isECNEnabled() bool { return !isECNDisabledUsingEnv() }
