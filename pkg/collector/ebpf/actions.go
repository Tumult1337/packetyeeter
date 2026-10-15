package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func (m *Maps) BlockIP(ip net.IP, reason string, meta logrus.Fields) error {
	// AllowList: Never block loopback, private networks (RFC1918), or link-local
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil
	}

	// Dynamic AllowList (User Configured)
	for _, subnet := range m.AllowedNets {
		if subnet.Contains(ip) {
			// Ensure we don't log spam if they are being noisy but allowed
			// Or should we log "Allowed but bad"? For now, just silently allow.
			return nil
		}
	}

	// Prepare log fields
	if meta == nil {
		meta = logrus.Fields{}
	}
	meta["ip"] = ip.String()

	// Only set "reason" if not provided in meta
	if _, ok := meta["reason"]; !ok {
		meta["reason"] = reason
	}

	if m.DryRun {
		meta["action"] = "WOULD BLOCK (Monitor Mode)"
		meta["level"] = "warning"
		// Ensure consistency with poller logs
		if _, ok := meta["proto"]; !ok {
			meta["proto"] = "TCP" // Default assumption if not provided
		}

		logrus.WithFields(meta).Warn(reason)
		// Fallthrough to write to map so XDP can count "would be blocked" packets
		// XDP will NOT drop because of the global monitor_mode flag.
	} else {
		meta["action"] = "Blocked temporarily"
		logrus.WithFields(meta).Warn(reason)
	}

	now, err := MonotonicNowNs()
	if err != nil {
		return fmt.Errorf("block %s: %w", ip, err)
	}

	if ip4 := ip.To4(); ip4 != nil {
		key := binary.LittleEndian.Uint32(ip4)
		if err := m.BlockedIPs.Put(key, now); err != nil {
			return fmt.Errorf("failed to block IPv4: %w", err)
		}
	} else {
		var key [16]byte
		copy(key[:], ip.To16())
		if err := m.BlockedIPsV6.Put(key, now); err != nil {
			return fmt.Errorf("failed to block IPv6: %w", err)
		}
	}

	meta["action"] = "Blocked temporarily"
	logrus.WithFields(meta).Warn(reason)
	return nil
}

func (m *Maps) UnblockIP(ip net.IP) error {
	if ip4 := ip.To4(); ip4 != nil {
		key := binary.LittleEndian.Uint32(ip4)
		return m.BlockedIPs.Delete(key)
	} else {
		var key [16]byte
		copy(key[:], ip.To16())
		return m.BlockedIPsV6.Delete(key)
	}
}

type MonotonicClock func() (uint64, error)

func MonotonicNowNs() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("read CLOCK_MONOTONIC: %w", err)
	}
	return uint64(ts.Nano()), nil
}

func blockRemaining(now, blockedAt uint64, blockDuration time.Duration) (time.Duration, bool) {
	if blockDuration <= 0 {
		return 0, blockedAt >= now
	}
	if blockedAt >= now {
		return blockDuration, true
	}
	elapsed := now - blockedAt
	durationNs := uint64(blockDuration)
	if elapsed >= durationNs {
		return 0, false
	}
	return time.Duration(durationNs - elapsed), true
}

func blockExpired(now, blockedAt uint64, blockDuration time.Duration) bool {
	_, active := blockRemaining(now, blockedAt, blockDuration)
	return !active
}

type BlockedIPInfo struct {
	IP           string `json:"ip"`
	RemainingTTL string `json:"remaining_ttl"`
}

type BlockedIPList struct {
	IPv4        []BlockedIPInfo `json:"ipv4"`
	IPv6        []BlockedIPInfo `json:"ipv6"`
	MonitorMode bool            `json:"monitor_mode"`
}

type blockMap interface {
	iterate() entryIterator
	Lookup(key, valueOut any) error
	Delete(key any) error
	String() string
}

type blockKey interface {
	uint32 | [16]byte
}

func v4KeyAddr(key uint32) netip.Addr {
	var octets [4]byte
	binary.LittleEndian.PutUint32(octets[:], key)
	return netip.AddrFrom4(octets)
}

func v6KeyAddr(key [16]byte) netip.Addr {
	return netip.AddrFrom16(key)
}

func listBlocks[K blockKey](m blockMap, toAddr func(K) netip.Addr, now uint64, blockDuration time.Duration) ([]BlockedIPInfo, error) {
	var infos []BlockedIPInfo
	var key K
	var blockedAt uint64
	iter := m.iterate()
	for iter.Next(&key, &blockedAt) {
		ttl := "expired"
		if remaining, active := blockRemaining(now, blockedAt, blockDuration); active {
			ttl = remaining.Round(time.Second).String()
		}
		infos = append(infos, BlockedIPInfo{IP: toAddr(key).String(), RemainingTTL: ttl})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s: %w", m, err)
	}
	return infos, nil
}

func (m *Maps) ListBlockedIPs(clock MonotonicClock, blockDuration time.Duration) ([]BlockedIPInfo, []BlockedIPInfo, error) {
	now, err := clock()
	if err != nil {
		return nil, nil, fmt.Errorf("list blocked IPs: %w", err)
	}
	v4, err := listBlocks(ciliumMap{m.BlockedIPs}, v4KeyAddr, now, blockDuration)
	if err != nil {
		return nil, nil, fmt.Errorf("list blocked IPv4: %w", err)
	}
	v6, err := listBlocks(ciliumMap{m.BlockedIPsV6}, v6KeyAddr, now, blockDuration)
	if err != nil {
		return nil, nil, fmt.Errorf("list blocked IPv6: %w", err)
	}
	return v4, v6, nil
}

type ExpiredBlock struct {
	Addr      netip.Addr
	BlockedAt uint64
}

func expiredBlocks[K blockKey](m blockMap, toAddr func(K) netip.Addr, now uint64, blockDuration time.Duration) ([]ExpiredBlock, error) {
	var expired []ExpiredBlock
	var key K
	var blockedAt uint64
	iter := m.iterate()
	for iter.Next(&key, &blockedAt) {
		if blockExpired(now, blockedAt, blockDuration) {
			expired = append(expired, ExpiredBlock{Addr: toAddr(key), BlockedAt: blockedAt})
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s: %w", m, err)
	}
	return expired, nil
}

func collectExpiredBlocks(v4, v6 blockMap, clock MonotonicClock, blockDuration time.Duration) ([]ExpiredBlock, error) {
	now, err := clock()
	if err != nil {
		return nil, fmt.Errorf("expired blocks: %w", err)
	}
	expired4, err := expiredBlocks(v4, v4KeyAddr, now, blockDuration)
	if err != nil {
		return nil, fmt.Errorf("expired IPv4 blocks: %w", err)
	}
	expired6, err := expiredBlocks(v6, v6KeyAddr, now, blockDuration)
	if err != nil {
		return nil, fmt.Errorf("expired IPv6 blocks: %w", err)
	}
	return append(expired4, expired6...), nil
}

func (m *Maps) ExpiredBlocks(clock MonotonicClock, blockDuration time.Duration) ([]ExpiredBlock, error) {
	return collectExpiredBlocks(ciliumMap{m.BlockedIPs}, ciliumMap{m.BlockedIPsV6}, clock, blockDuration)
}

func deleteIfUnchanged[K blockKey](m blockMap, key K, blockedAt uint64) (bool, error) {
	var current uint64
	if err := m.Lookup(key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("lookup %s: %w", m, err)
	}
	if current != blockedAt {
		return false, nil
	}
	if err := m.Delete(key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("delete %s: %w", m, err)
	}
	return true, nil
}

func deleteExpiredBlock(v4, v6 blockMap, block ExpiredBlock) (bool, error) {
	if block.Addr.Is4() {
		return deleteIfUnchanged(v4, binary.LittleEndian.Uint32(block.Addr.AsSlice()), block.BlockedAt)
	}
	if block.Addr.Is6() {
		return deleteIfUnchanged(v6, block.Addr.As16(), block.BlockedAt)
	}
	return false, fmt.Errorf("delete expired block: invalid address %v", block.Addr)
}

func (m *Maps) DeleteExpiredBlock(block ExpiredBlock) (bool, error) {
	return deleteExpiredBlock(ciliumMap{m.BlockedIPs}, ciliumMap{m.BlockedIPsV6}, block)
}
