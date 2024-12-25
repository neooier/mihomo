//go:build !windows

package icmp

import (
	"net"

	"golang.org/x/net/icmp"
)

func newICMPListener(address ICMPAddr) (net.PacketConn, error) {

	conn, err := icmp.ListenPacket("udp6", address.String())
	if err != nil {
		return nil, err
	}

	return conn, nil
}
