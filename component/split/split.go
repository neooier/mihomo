package split

import (
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/cmd"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const defaultTableStart = 20000

type entry struct {
	name    string
	tableID int
}

type manager struct {
	mu               sync.RWMutex
	enabled          bool
	interfaceName    string
	localInterfaceIP netip.Addr
	entries          map[netip.Addr]*entry
	nextTableID      int
}

var defaultManager = &manager{
	entries:     make(map[netip.Addr]*entry),
	nextTableID: defaultTableStart,
}

func Configure(enabled bool, interfaceName string, localInterfaceIP netip.Addr) {
	defaultManager.configure(enabled, interfaceName, localInterfaceIP)
}

func EnsureForMetadata(metadata *C.Metadata) {
	defaultManager.ensureForMetadata(metadata)
}

func Cleanup() {
	defaultManager.configure(false, "", netip.Addr{})
}

func Enabled() bool {
	return defaultManager.enabledState()
}

func InterfaceName() string {
	return defaultManager.interfaceNameState()
}

func LocalInterfaceIP() netip.Addr {
	return defaultManager.localInterfaceState()
}

func (m *manager) enabledState() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

func (m *manager) interfaceNameState() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.interfaceName
}

func (m *manager) localInterfaceState() netip.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.localInterfaceIP
}

func (m *manager) configure(enabled bool, interfaceName string, localInterfaceIP netip.Addr) {
	var cleanupEntries map[netip.Addr]*entry
	m.mu.Lock()
	prevEnabled := m.enabled
	prevInterface := m.interfaceName
	m.enabled = enabled
	m.interfaceName = interfaceName
	m.localInterfaceIP = localInterfaceIP
	if m.entries == nil {
		m.entries = make(map[netip.Addr]*entry)
	}
	if !enabled || (prevEnabled && prevInterface != "" && prevInterface != interfaceName) {
		cleanupEntries = m.entries
		m.entries = make(map[netip.Addr]*entry)
		m.nextTableID = defaultTableStart
	}
	m.mu.Unlock()

	if cleanupEntries != nil {
		cleanup(cleanupEntries)
	}

	if enabled && interfaceName == "" {
		log.Warnln("[Split] enabled but interface-name is empty")
	}
}

func (m *manager) ensureForMetadata(metadata *C.Metadata) {
	if metadata == nil || runtime.GOOS != "linux" {
		return
	}

	m.mu.RLock()
	enabled := m.enabled
	interfaceName := m.interfaceName
	localInterfaceIP := m.localInterfaceIP
	m.mu.RUnlock()

	if !enabled || interfaceName == "" {
		return
	}

	ip := metadata.SrcIP
	if metadata.Type == C.INNER || !ip.IsValid() {
		ip = localInterfaceIP
	}
	if !ip.IsValid() {
		return
	}

	m.ensureForIP(ip, interfaceName)
}

func (m *manager) ensureForIP(ip netip.Addr, parentInterface string) {
	m.mu.Lock()
	if existing := m.entries[ip]; existing != nil {
		m.mu.Unlock()
		return
	}
	entry := &entry{name: interfaceNameForIP(ip), tableID: m.nextTableID}
	m.nextTableID++
	m.entries[ip] = entry
	m.mu.Unlock()

	if err := setupInterface(ip, parentInterface, entry); err != nil {
		log.Warnln("[Split] setup for %s failed: %v", ip, err)
		m.mu.Lock()
		delete(m.entries, ip)
		m.mu.Unlock()
	}
}

func interfaceNameForIP(ip netip.Addr) string {
	h := fnv.New32a()
	_, _ = h.Write(ip.AsSlice())
	return fmt.Sprintf("mhv%x", h.Sum32())
}

func setupInterface(ip netip.Addr, parentInterface string, entry *entry) error {
	if _, err := net.InterfaceByName(parentInterface); err != nil {
		return fmt.Errorf("parent interface %s not found", parentInterface)
	}

	if _, err := net.InterfaceByName(entry.name); err != nil {
		if _, err := cmd.ExecCmd(fmt.Sprintf("ip link add %s link %s type macvlan mode bridge", entry.name, parentInterface)); err != nil {
			return fmt.Errorf("create macvlan %s failed: %w", entry.name, err)
		}
	}

	if _, err := cmd.ExecCmd(fmt.Sprintf("ip link set %s up", entry.name)); err != nil {
		return fmt.Errorf("set interface %s up failed: %w", entry.name, err)
	}

	if _, err := cmd.ExecCmd(fmt.Sprintf("udhcpc -i %s -b", entry.name)); err != nil {
		log.Warnln("[Split] udhcpc for %s failed: %v", entry.name, err)
	}

	gateway, err := findGateway(entry.name)
	if err != nil {
		log.Warnln("[Split] lookup gateway for %s failed: %v", entry.name, err)
	}

	if gateway != "" {
		if _, err := cmd.ExecCmd(fmt.Sprintf("ip route replace table %d default via %s dev %s", entry.tableID, gateway, entry.name)); err != nil {
			return fmt.Errorf("add default route for %s failed: %w", entry.name, err)
		}
	} else {
		if _, err := cmd.ExecCmd(fmt.Sprintf("ip route replace table %d default dev %s", entry.tableID, entry.name)); err != nil {
			return fmt.Errorf("add default route for %s failed: %w", entry.name, err)
		}
	}

	if _, err := cmd.ExecCmd(fmt.Sprintf("ip rule add from %s lookup %d", ip.String(), entry.tableID)); err != nil {
		return fmt.Errorf("add ip rule for %s failed: %w", ip, err)
	}

	return nil
}

func findGateway(interfaceName string) (string, error) {
	output, err := cmd.ExecCmd(fmt.Sprintf("ip route show dev %s default", interfaceName))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(output)
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", nil
}

func cleanup(entries map[netip.Addr]*entry) {
	if runtime.GOOS != "linux" {
		return
	}

	for ip, entry := range entries {
		_, _ = cmd.ExecCmd(fmt.Sprintf("ip rule del from %s lookup %d", ip.String(), entry.tableID))
		_, _ = cmd.ExecCmd(fmt.Sprintf("ip link del %s", entry.name))
	}
}
