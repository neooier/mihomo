//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

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
	cancel    context.CancelFunc
}

var globalSplitManager = &splitManager{
	entries: make(map[netip.Addr]*splitEntry),
}

var errSplitSkip = errors.New("split skip")
var splitAllowedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.168.100.0/24"),
}

func SetSplitParentInterface(name string) {
	globalSplitManager.mu.Lock()
	defer globalSplitManager.mu.Unlock()
	globalSplitManager.parentIface = name
}

func ensureSplitProxy(metadata *C.Metadata) (string, error) {
	srcIP := metadata.SrcIP.Unmap()
	if !srcIP.Is4() {
		return "", fmt.Errorf("split mode only supports IPv4 source addresses")
	}
	allowed := false
	for _, prefix := range splitAllowedPrefixes {
		if prefix.Contains(srcIP) {
			allowed = true
			break
		}
	}
	if !allowed {
		log.Debugln("[SPLIT] skip interface selection for %s (source not in split allowlist)", metadata.SourceDetail())
		return "", errSplitSkip
	}
	if metadata.DstPort == 53 || metadata.Type == C.INNER {
		return "", errSplitSkip
	}
	return globalSplitManager.getOrCreate(srcIP)
}

func (m *splitManager) getOrCreate(srcIP netip.Addr) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.entries[srcIP]; ok {
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

	leaseCtx, cancel := context.WithCancel(context.Background())
	m.entries[srcIP] = &splitEntry{
		ifaceName: ifaceName,
		cancel:    cancel,
	}
	go m.runUDHCPC(leaseCtx, srcIP, ifaceName)
	log.Debugln("[SPLIT] assigned interface %s for %s", ifaceName, srcIP)
	return ifaceName, nil
}

func (m *splitManager) runUDHCPC(ctx context.Context, srcIP netip.Addr, ifaceName string) {
	for {
		cmd := exec.CommandContext(ctx, "udhcpc", "-f", "-i", ifaceName)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		log.Infoln("[SPLIT] start udhcpc on %s for %s", ifaceName, srcIP)
		err := cmd.Run()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Warnln("[SPLIT] udhcpc on %s exited: %v", ifaceName, err)
		}
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func isExists(err error) bool {
	if errno, ok := err.(unix.Errno); ok && errno == unix.EEXIST {
		return true
	}
	return false
}
