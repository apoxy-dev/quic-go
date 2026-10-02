//go:build !linux && !windows && !darwin

package quic

import (
	"syscall"
)

func setDF(syscall.RawConn) (bool, error) {
	// no-op on unsupported platforms
	return false, nil
}

func isSendMsgSizeErr(err error) bool {
	// to be implemented for more specific platforms
	return false
}

func isRecvMsgSizeErr(err error) bool {
	// to be implemented for more specific platforms
	return false
}

// isNoRouteErr is not known on these platforms, so a send that fails for no
// route ends the connection.
func isNoRouteErr(error) bool { return false }
