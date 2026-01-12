//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

type splitManager struct {
	mu          sync.Mutex
	parentIface string
	entries     map[netip.Addr]*splitEntry
}

type splitEntry struct {
	ifaceName string
	expires   time.Time
}

var globalSplitManager = &splitManager{
	entries: make(map[netip.Addr]*splitEntry),
}

var errSplitSkip = errors.New("split skip")

func SetSplitParentInterface(name string) {
	globalSplitManager.mu.Lock()
	defer globalSplitManager.mu.Unlock()
	globalSplitManager.parentIface = name
}

func ensureSplitProxy(metadata *C.Metadata) (string, error) {
	if !metadata.SrcIP.Is4() {
		return "", fmt.Errorf("split mode only supports IPv4 source addresses")
	}
	if metadata.DstPort == 53 || metadata.Type == C.INNER {
		return "", errSplitSkip
	}
	return globalSplitManager.getOrCreate(metadata.SrcIP)
}

func (m *splitManager) getOrCreate(srcIP netip.Addr) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.entries[srcIP]; ok && time.Until(entry.expires) > 30*time.Second {
		log.Debugln("[SPLIT] reuse interface %s for %s", entry.ifaceName, srcIP)
		return entry.ifaceName, nil
	}

	if m.parentIface == "" {
		return "", fmt.Errorf("split mode requires `interface-name` to be configured")
	}

	link, err := netlink.LinkByName(m.parentIface)
	if err != nil {
		return "", fmt.Errorf("query parent interface %s: %w", m.parentIface, err)
	}

	srcBytes := srcIP.As4()
	ifaceName := fmt.Sprintf("%s-%02x%02x%02x%02x", m.parentIface, srcBytes[0], srcBytes[1], srcBytes[2], srcBytes[3])
	macvlan := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        ifaceName,
			ParentIndex: link.Attrs().Index,
		},
		Mode: netlink.MACVLAN_MODE_BRIDGE,
	}
	if err := netlink.LinkAdd(macvlan); err != nil && !isExists(err) {
		return "", fmt.Errorf("create macvlan %s: %w", ifaceName, err)
	}
	if err := netlink.LinkSetUp(macvlan); err != nil {
		return "", fmt.Errorf("set macvlan up: %w", err)
	}

	if err := m.acquireDHCP(ifaceName, macvlan); err != nil {
		return "", err
	}

	m.entries[srcIP] = &splitEntry{
		ifaceName: ifaceName,
		expires:   time.Now().Add(time.Hour),
	}
	log.Debugln("[SPLIT] assigned interface %s for %s", ifaceName, srcIP)
	return ifaceName, nil
}

func (m *splitManager) acquireDHCP(ifaceName string, link netlink.Link) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := nclient4.New(ifaceName, nclient4.WithTimeout(5*time.Second), nclient4.WithRetry(1))
	if err != nil {
		return fmt.Errorf("init dhcp client: %w", err)
	}
	lease, err := client.Request(ctx)
	if err != nil {
		return fmt.Errorf("dhcp request on %s: %w", ifaceName, err)
	}

	ip := lease.ACK.YourIPAddr
	mask := lease.ACK.SubnetMask()
	if ip == nil || mask == nil {
		return fmt.Errorf("dhcp lease missing ip or mask")
	}

	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip.Mask(mask),
			Mask: mask,
		},
	}
	if err := netlink.AddrAdd(link, addr); err != nil && !isExists(err) {
		return fmt.Errorf("assign address to %s: %w", ifaceName, err)
	}

	routers := lease.ACK.Router()
	if len(routers) > 0 {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        routers[0],
		}
		if err := netlink.RouteAdd(route); err != nil && !isExists(err) {
			return fmt.Errorf("add default route on %s: %w", ifaceName, err)
		}
	}
	log.Infoln("[SPLIT] macvlan %s leased %s via %v", ifaceName, ip, routers)
	return nil
}

func isExists(err error) bool {
	if errno, ok := err.(unix.Errno); ok && errno == unix.EEXIST {
		return true
	}
	return false
}
