package icmp

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	SERVER_SYM = byte('S')
	CLIENT_SYM = byte('C')
)

func hexStringToFixedByteArray(hexStr string) ([3]byte, error) {
	var result [3]byte

	// 解码十六进制字符串为字节切片
	byteSlice, err := hex.DecodeString(hexStr)
	if err != nil {
		return result, fmt.Errorf("hex decode error: %v", err)
	}

	// 检查解码后的字节数是否正好是4个
	if len(byteSlice) != 3 {
		return result, fmt.Errorf("input length is not 4 bytes")
	}

	// 将字节切片复制到固定大小的数组
	copy(result[:], byteSlice)

	return result, nil
}

type ClientConn struct {
	rAddr    net.UDPAddr
	lAddr    string
	sym      [3]byte
	listener net.PacketConn
	sender   net.Conn
	isServer bool
}

func (c ClientConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var _p = make([]byte, 1800)
	for {
		n, addr, err = c.listener.ReadFrom(_p)
		if err != nil {
			//log.Println(err)
			continue
		}

		msg, _err := icmp.ParseMessage(58, _p[:n])
		if _err != nil {
			//log.Println(_err)
			continue
		}
		echoReq, ok := msg.Body.(*icmp.Echo)
		if !ok {
			//log.Println("Could not cast body to *icmp.Echo")
			continue
		}

		if echoReq.Data[0] != c.sym[0] || echoReq.Data[1] != c.sym[1] || echoReq.Data[2] != c.sym[2] {
			continue
		}
		if c.isServer {
			if echoReq.Data[3] != CLIENT_SYM {
				continue
			}
		} else {
			if echoReq.Data[3] != SERVER_SYM {
				continue
			}
		}
		copy(p, echoReq.Data[4:])
		n = len(echoReq.Data[4:])
		//fmt.Printf("readfrom:%d %s %d\n\n", time.Now().UnixMilli(), c.rAddr.String(), n)
		return
	}

}

func (c ClientConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	//fmt.Printf("writeto:%d %s %d\n\n", time.Now().UnixMilli(), addr.String(), len(p))
	var CS_SYM byte
	if c.isServer {
		CS_SYM = SERVER_SYM
	} else {
		CS_SYM = CLIENT_SYM
	}
	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   18,
			Seq:  1,
			Data: append(append(c.sym[:], CS_SYM), p...),
		},
	}
	//fmt.Printf("%d ?size\n", len(append(append(c.sym[:], CS_SYM), p...)))
	wm, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	if c.isServer {
		_, err = c.listener.WriteTo(wm, addr)
	} else {
		_, err = c.sender.Write(wm)
	}
	n = len(p)
	return
}

func (c ClientConn) Close() error {
	// err0 := c.listener.Close()
	// err1 := c.sender.Close()
	// if err0 != nil {
	// 	return err0
	// }
	// if err1 != nil {
	// 	return err1
	// }
	return nil
}

func (c ClientConn) LocalAddr() net.Addr {
	return &c.rAddr
}

func (c ClientConn) SetDeadline(t time.Time) error {
	err0 := c.listener.SetDeadline(t)
	if err0 != nil {
		return err0
	}
	if !c.isServer {
		err1 := c.sender.SetDeadline(t)

		if err1 != nil {
			return err1
		}
	}

	return nil
}

func (c ClientConn) SetReadDeadline(t time.Time) error {
	err0 := c.listener.SetReadDeadline(t)
	if err0 != nil {
		return err0
	}
	if !c.isServer {
		err1 := c.sender.SetReadDeadline(t)

		if err1 != nil {
			return err1
		}
	}

	return nil
}

func (c ClientConn) SetWriteDeadline(t time.Time) error {
	err0 := c.listener.SetWriteDeadline(t)
	if err0 != nil {
		return err0
	}
	if !c.isServer {
		err1 := c.sender.SetWriteDeadline(t)

		if err1 != nil {
			return err1
		}
	}

	return nil
}

func Connect(address string, rAddr net.UDPAddr, ssym string, isServer bool) (net.PacketConn, error) {
	sym, err := hexStringToFixedByteArray(ssym)
	if err != nil {
		return nil, err
	}
	listener, err := newICMPListener(address)
	if err != nil {
		return nil, err
	}
	var sender net.Conn
	if !isServer {
		sender, err = net.Dial("ip6:ipv6-icmp", rAddr.IP.String())
		if err != nil {
			return nil, err
		}
	}

	return ClientConn{
		listener: listener,
		sender:   sender,
		rAddr:    rAddr,
		lAddr:    address,
		sym:      sym,
		isServer: isServer,
	}, nil
}
