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
	lastIPNet *net.IPNet
	router    net.IP
	cancel    context.CancelFunc
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

	if entry, ok := m.entries[srcIP]; ok {
		if time.Until(entry.expires) > 30*time.Second {
			log.Debugln("[SPLIT] reuse interface %s for %s", entry.ifaceName, srcIP)
			return entry.ifaceName, nil
		}
		if entry.cancel != nil {
			entry.cancel()
		}
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

	lease, client, err := m.acquireDHCP(ifaceName, macvlan, nil)
	if err != nil {
		return "", err
	}

	leaseTime := lease.ACK.IPAddressLeaseTime(time.Hour)
	renewTime := lease.ACK.IPAddressRenewalTime(leaseTime / 2)
	leaseCtx, cancel := context.WithCancel(context.Background())
	m.entries[srcIP] = &splitEntry{
		ifaceName: ifaceName,
		expires:   time.Now().Add(leaseTime),
		lastIPNet: leaseIPNet(lease),
		router:    leaseRouter(lease),
		cancel:    cancel,
	}
	go m.renewLeaseLoop(leaseCtx, srcIP, ifaceName, client, lease, renewTime, leaseTime)
	log.Debugln("[SPLIT] assigned interface %s for %s", ifaceName, srcIP)
	return ifaceName, nil
}

func (m *splitManager) acquireDHCP(ifaceName string, link netlink.Link, oldIPNet *net.IPNet) (*nclient4.Lease, *nclient4.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := nclient4.New(ifaceName, nclient4.WithTimeout(5*time.Second), nclient4.WithRetry(1))
	if err != nil {
		return nil, nil, fmt.Errorf("init dhcp client: %w", err)
	}
	lease, err := client.Request(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("dhcp request on %s: %w", ifaceName, err)
	}

	if err := m.applyLease(link, ifaceName, lease, oldIPNet, nil); err != nil {
		return nil, nil, err
	}

	return lease, client, nil
}

func (m *splitManager) applyLease(link netlink.Link, ifaceName string, lease *nclient4.Lease, oldIPNet *net.IPNet, oldRouter net.IP) error {
	ipnet := leaseIPNet(lease)
	if ipnet == nil {
		return fmt.Errorf("dhcp lease missing ip or mask")
	}
	if oldIPNet != nil && !oldIPNet.IP.Equal(ipnet.IP) {
		_ = netlink.AddrDel(link, &netlink.Addr{IPNet: oldIPNet})
	}
	addr := &netlink.Addr{IPNet: ipnet}
	if err := netlink.AddrAdd(link, addr); err != nil && !isExists(err) {
		return fmt.Errorf("assign address to %s: %w", ifaceName, err)
	}

	router := leaseRouter(lease)
	if len(oldRouter) > 0 && router != nil && !oldRouter.Equal(router) {
		_ = netlink.RouteDel(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        oldRouter,
		})
	}
	if router != nil {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        router,
		}
		if err := netlink.RouteAdd(route); err != nil && !isExists(err) {
			return fmt.Errorf("add default route on %s: %w", ifaceName, err)
		}
	}
	log.Infoln("[SPLIT] macvlan %s leased %s via %v", ifaceName, ipnet.IP, router)
	return nil
}

func (m *splitManager) renewLeaseLoop(ctx context.Context, srcIP netip.Addr, ifaceName string, client *nclient4.Client, lease *nclient4.Lease, renewTime time.Duration, leaseTime time.Duration) {
	for {
		wait := renewTime
		if wait <= 0 {
			wait = leaseTime / 2
		}
		if wait <= 0 {
			wait = 30 * time.Minute
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}

		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			log.Warnln("[SPLIT] renew link %s for %s failed: %v", ifaceName, srcIP, err)
			continue
		}

		renewCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		newLease, err := client.Renew(renewCtx, lease)
		cancel()
		if err != nil {
			log.Warnln("[SPLIT] renew lease on %s failed: %v", ifaceName, err)
			newLease, client, err = m.acquireDHCP(ifaceName, link, leaseIPNet(lease))
			if err != nil {
				log.Warnln("[SPLIT] re-request lease on %s failed: %v", ifaceName, err)
				continue
			}
		} else {
			if err := m.applyLease(link, ifaceName, newLease, leaseIPNet(lease), leaseRouter(lease)); err != nil {
				log.Warnln("[SPLIT] apply renewed lease on %s failed: %v", ifaceName, err)
				continue
			}
		}

		lease = newLease
		leaseTime = lease.ACK.IPAddressLeaseTime(leaseTime)
		renewTime = lease.ACK.IPAddressRenewalTime(leaseTime / 2)

		m.mu.Lock()
		if entry, ok := m.entries[srcIP]; ok {
			entry.expires = time.Now().Add(leaseTime)
			entry.lastIPNet = leaseIPNet(lease)
			entry.router = leaseRouter(lease)
		}
		m.mu.Unlock()
		log.Debugln("[SPLIT] renewed lease on %s for %s", ifaceName, srcIP)
	}
}

func leaseIPNet(lease *nclient4.Lease) *net.IPNet {
	ip := lease.ACK.YourIPAddr
	mask := lease.ACK.SubnetMask()
	if ip == nil || mask == nil {
		return nil
	}
	return &net.IPNet{
		IP:   ip.Mask(mask),
		Mask: mask,
	}
}

func leaseRouter(lease *nclient4.Lease) net.IP {
	routers := lease.ACK.Router()
	if len(routers) == 0 {
		return nil
	}
	return routers[0]
}

func isExists(err error) bool {
	if errno, ok := err.(unix.Errno); ok && errno == unix.EEXIST {
		return true
	}
	return false
}
