//go:build linux && (amd64 || arm64)

package quic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// mmsghdr is struct mmsghdr of recvmmsg(2). x/sys has no type for it.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

// mmsgConn reads a batch of packets with recvmmsg.
// It gives the same *net.UDPAddr again while the sender does not change.
type mmsgConn struct {
	rc    syscall.RawConn
	laddr net.Addr
	read  func(fd uintptr) bool

	hs    [batchSize]mmsghdr
	iovs  [batchSize]unix.Iovec
	names [batchSize]unix.RawSockaddrAny
	vlen  int
	flags int
	n     int
	errno syscall.Errno

	lastName [unix.SizeofSockaddrAny]byte
	lastLen  int
	lastAddr *net.UDPAddr
	zoneID   uint32
	zone     string
}

// newMmsgConn returns nil if the conn is not a UDP conn.
func newMmsgConn(rc syscall.RawConn, laddr net.Addr) batchConn {
	if _, ok := laddr.(*net.UDPAddr); !ok {
		return nil
	}
	c := &mmsgConn{rc: rc, laddr: laddr}
	c.read = c.recvmmsg
	return c
}

// ReadBatch reads into Buffers[0] of each message.
func (c *mmsgConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	ms = ms[:min(len(ms), len(c.hs))]
	if len(ms) == 0 {
		return 0, nil
	}
	for i := range ms {
		h := &c.hs[i]
		*h = mmsghdr{}
		h.Hdr.Name = (*byte)(unsafe.Pointer(&c.names[i]))
		h.Hdr.Namelen = unix.SizeofSockaddrAny
		if len(ms[i].Buffers) > 0 && len(ms[i].Buffers[0]) > 0 {
			c.iovs[i].Base = &ms[i].Buffers[0][0]
			c.iovs[i].SetLen(len(ms[i].Buffers[0]))
			h.Hdr.Iov = &c.iovs[i]
			h.Hdr.SetIovlen(1)
		}
		if len(ms[i].OOB) > 0 {
			h.Hdr.Control = &ms[i].OOB[0]
			h.Hdr.SetControllen(len(ms[i].OOB))
		}
	}
	c.vlen, c.flags, c.n, c.errno = len(ms), flags, 0, 0
	if err := c.rc.Read(c.read); err != nil {
		return 0, c.opError(err)
	}
	if c.errno != 0 {
		return 0, c.opError(os.NewSyscallError("recvmmsg", c.errno))
	}
	for i := 0; i < c.n; i++ {
		h := &c.hs[i]
		ms[i].N = int(h.Len)
		ms[i].NN = int(h.Hdr.Controllen)
		ms[i].Flags = int(h.Hdr.Flags)
		addr, err := c.addr(i, int(h.Hdr.Namelen))
		if err != nil {
			return c.n, c.opError(err)
		}
		ms[i].Addr = addr
	}
	return c.n, nil
}

func (c *mmsgConn) recvmmsg(fd uintptr) bool {
	n, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&c.hs[0])), uintptr(c.vlen), uintptr(c.flags), 0, 0)
	if errno == unix.EAGAIN && c.flags&unix.MSG_DONTWAIT == 0 {
		return false // Wait until the socket is readable.
	}
	if errno != 0 {
		c.errno = errno
		return true
	}
	c.n = int(n)
	return true
}

func (c *mmsgConn) opError(err error) error {
	return &net.OpError{Op: "read", Net: c.laddr.Network(), Source: c.laddr, Err: err}
}

// addr returns the last address when the raw sockaddr is the same as the last one.
func (c *mmsgConn) addr(i, namelen int) (*net.UDPAddr, error) {
	name := (*[unix.SizeofSockaddrAny]byte)(unsafe.Pointer(&c.names[i]))[:min(namelen, unix.SizeofSockaddrAny)]
	if c.lastAddr != nil && bytes.Equal(name, c.lastName[:c.lastLen]) {
		return c.lastAddr, nil
	}
	a, err := c.parseAddr(name)
	if err != nil {
		return nil, err
	}
	c.lastLen = copy(c.lastName[:], name)
	c.lastAddr = a
	return a, nil
}

// parseAddr makes the same address as x/net.
func (c *mmsgConn) parseAddr(b []byte) (*net.UDPAddr, error) {
	if len(b) < 4 {
		return nil, errors.New("invalid address")
	}
	var ip net.IP
	var zone string
	switch binary.NativeEndian.Uint16(b) {
	case unix.AF_INET:
		if len(b) < unix.SizeofSockaddrInet4 {
			return nil, errors.New("short address")
		}
		ip = make(net.IP, net.IPv4len)
		copy(ip, b[4:8])
	case unix.AF_INET6:
		if len(b) < unix.SizeofSockaddrInet6 {
			return nil, errors.New("short address")
		}
		ip = make(net.IP, net.IPv6len)
		copy(ip, b[8:24])
		if id := binary.NativeEndian.Uint32(b[24:28]); id > 0 {
			zone = c.zoneName(id)
		}
	}
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(b[2:4])), Zone: zone}, nil
}

// zoneName keeps the name of the last zone.
func (c *mmsgConn) zoneName(id uint32) string {
	if id != c.zoneID {
		c.zoneID = id
		c.zone = strconv.Itoa(int(id))
		if ifi, err := net.InterfaceByIndex(int(id)); err == nil {
			c.zone = ifi.Name
		}
	}
	return c.zone
}
