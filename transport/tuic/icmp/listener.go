//go:build !windows

package icmp

import (
	"net"

	"golang.org/x/net/icmp"
)

func newICMPListener(address string) (net.PacketConn, error) {

	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", address)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
