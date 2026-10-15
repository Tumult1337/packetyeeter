package ebpf

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

type fakeBlockMap[K blockKey] struct {
	entries  map[K]uint64
	order    []K
	iterErr  error
	onLookup func(K)
	deletes  []K
}

func newFakeBlockMap[K blockKey]() *fakeBlockMap[K] {
	return &fakeBlockMap[K]{entries: map[K]uint64{}}
}

func (m *fakeBlockMap[K]) put(key K, blockedAt uint64) {
	if _, ok := m.entries[key]; !ok {
		m.order = append(m.order, key)
	}
	m.entries[key] = blockedAt
}

func (m *fakeBlockMap[K]) String() string { return "fake-block" }

func (m *fakeBlockMap[K]) Lookup(key, valueOut any) error {
	k := key.(K)
	if m.onLookup != nil {
		m.onLookup(k)
	}
	v, ok := m.entries[k]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*uint64) = v
	return nil
}

func (m *fakeBlockMap[K]) Delete(key any) error {
	k := key.(K)
	if _, ok := m.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, k)
	m.deletes = append(m.deletes, k)
	return nil
}

type fakeBlockIter[K blockKey] struct {
	m   *fakeBlockMap[K]
	pos int
}

func (it *fakeBlockIter[K]) Next(k, v any) bool {
	for it.pos < len(it.m.order) {
		key := it.m.order[it.pos]
		it.pos++
		if val, ok := it.m.entries[key]; ok {
			*k.(*K), *v.(*uint64) = key, val
			return true
		}
	}
	return false
}

func (it *fakeBlockIter[K]) Err() error { return it.m.iterErr }

func (m *fakeBlockMap[K]) iterate() entryIterator { return &fakeBlockIter[K]{m: m} }

func fixedClock(now uint64) MonotonicClock {
	return func() (uint64, error) { return now, nil }
}

func v4Key(t *testing.T, s string) uint32 {
	t.Helper()
	octets := netip.MustParseAddr(s).As4()
	return binary.LittleEndian.Uint32(octets[:])
}

func TestBlockExpired(t *testing.T) {
	const duration = 300 * time.Second
	const ns = uint64(duration)
	cases := []struct {
		name      string
		now       uint64
		blockedAt uint64
		want      bool
	}{
		{"clock zero, block at zero", 0, 0, false},
		{"clock zero, block in past of real clock", 0, 5_000_000_000, false},
		{"block written after clock read", 10 * ns, 10*ns + 1, false},
		{"block written at clock read", 10 * ns, 10 * ns, false},
		{"one ns before boundary", 10 * ns, 9*ns + 1, false},
		{"exactly at boundary", 10 * ns, 9 * ns, true},
		{"long expired", 10 * ns, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := blockExpired(tc.now, tc.blockedAt, duration); got != tc.want {
				t.Fatalf("blockExpired(%d, %d) = %v, want %v", tc.now, tc.blockedAt, got, tc.want)
			}
		})
	}
}

func TestCollectExpiredBlocksClockErrorSelectsNothing(t *testing.T) {
	v4 := newFakeBlockMap[uint32]()
	v4.put(v4Key(t, "198.51.100.7"), 1)
	v6 := newFakeBlockMap[[16]byte]()
	v6.put(netip.MustParseAddr("2001:db8::1").As16(), 1)
	clockErr := errors.New("clock unavailable")

	expired, err := collectExpiredBlocks(v4, v6, func() (uint64, error) { return 0, clockErr }, time.Minute)
	if !errors.Is(err, clockErr) {
		t.Fatalf("err = %v, want %v", err, clockErr)
	}
	if len(expired) != 0 {
		t.Fatalf("expired = %v, want none", expired)
	}
}

func TestCollectExpiredBlocksSelectsOnlyExpired(t *testing.T) {
	const now = uint64(1000 * time.Second)
	v4 := newFakeBlockMap[uint32]()
	v4.put(v4Key(t, "198.51.100.7"), now-uint64(2*time.Minute))
	v4.put(v4Key(t, "198.51.100.8"), now-uint64(30*time.Second))
	v4.put(v4Key(t, "198.51.100.9"), now+5)
	v6 := newFakeBlockMap[[16]byte]()
	v6.put(netip.MustParseAddr("2001:db8::1").As16(), now-uint64(time.Minute))
	v6.put(netip.MustParseAddr("2001:db8::2").As16(), now+5)

	expired, err := collectExpiredBlocks(v4, v6, fixedClock(now), time.Minute)
	if err != nil {
		t.Fatalf("collectExpiredBlocks: %v", err)
	}
	want := []ExpiredBlock{
		{Addr: netip.MustParseAddr("198.51.100.7"), BlockedAt: now - uint64(2*time.Minute)},
		{Addr: netip.MustParseAddr("2001:db8::1"), BlockedAt: now - uint64(time.Minute)},
	}
	if len(expired) != len(want) {
		t.Fatalf("expired = %v, want %v", expired, want)
	}
	for i := range want {
		if expired[i] != want[i] {
			t.Fatalf("expired[%d] = %v, want %v", i, expired[i], want[i])
		}
	}
}

func TestCollectExpiredBlocksReturnsIteratorError(t *testing.T) {
	iterErr := errors.New("iteration aborted")
	for _, failV6 := range []bool{false, true} {
		v4 := newFakeBlockMap[uint32]()
		v4.put(v4Key(t, "198.51.100.7"), 1)
		v6 := newFakeBlockMap[[16]byte]()
		if failV6 {
			v6.iterErr = iterErr
		} else {
			v4.iterErr = iterErr
		}

		expired, err := collectExpiredBlocks(v4, v6, fixedClock(uint64(time.Hour)), time.Minute)
		if !errors.Is(err, iterErr) {
			t.Fatalf("failV6=%v: err = %v, want %v", failV6, err, iterErr)
		}
		if len(expired) != 0 {
			t.Fatalf("failV6=%v: expired = %v, want none", failV6, expired)
		}
	}
}

func TestDeleteExpiredBlockKeepsReblock(t *testing.T) {
	const blockedAt = uint64(5)
	v4 := newFakeBlockMap[uint32]()
	v6 := newFakeBlockMap[[16]byte]()
	key := v4Key(t, "198.51.100.7")
	v4.put(key, blockedAt)
	v4.onLookup = func(k uint32) { v4.entries[k] = blockedAt + uint64(time.Hour) }

	deleted, err := deleteExpiredBlock(v4, v6, ExpiredBlock{Addr: netip.MustParseAddr("198.51.100.7"), BlockedAt: blockedAt})
	if err != nil {
		t.Fatalf("deleteExpiredBlock: %v", err)
	}
	if deleted || len(v4.deletes) != 0 {
		t.Fatalf("deleted = %v, deletes = %v; want re-block kept", deleted, v4.deletes)
	}
}

func TestDeleteExpiredBlockDeletesUnchanged(t *testing.T) {
	const blockedAt = uint64(5)
	v4 := newFakeBlockMap[uint32]()
	v6 := newFakeBlockMap[[16]byte]()
	v4.put(v4Key(t, "198.51.100.7"), blockedAt)
	v6Addr := netip.MustParseAddr("2001:db8::1")
	v6.put(v6Addr.As16(), blockedAt)

	for _, block := range []ExpiredBlock{
		{Addr: netip.MustParseAddr("198.51.100.7"), BlockedAt: blockedAt},
		{Addr: v6Addr, BlockedAt: blockedAt},
	} {
		deleted, err := deleteExpiredBlock(v4, v6, block)
		if err != nil || !deleted {
			t.Fatalf("deleteExpiredBlock(%v) = %v, %v; want true, nil", block.Addr, deleted, err)
		}
	}
	if len(v4.entries) != 0 || len(v6.entries) != 0 {
		t.Fatalf("entries left: v4=%v v6=%v", v4.entries, v6.entries)
	}
}

func TestDeleteExpiredBlockMissingKey(t *testing.T) {
	v4 := newFakeBlockMap[uint32]()
	v6 := newFakeBlockMap[[16]byte]()

	deleted, err := deleteExpiredBlock(v4, v6, ExpiredBlock{Addr: netip.MustParseAddr("198.51.100.7"), BlockedAt: 5})
	if err != nil || deleted {
		t.Fatalf("deleteExpiredBlock = %v, %v; want false, nil", deleted, err)
	}
}

func TestDeleteExpiredBlockRejectsInvalidAddr(t *testing.T) {
	v4 := newFakeBlockMap[uint32]()
	v6 := newFakeBlockMap[[16]byte]()

	if _, err := deleteExpiredBlock(v4, v6, ExpiredBlock{}); err == nil {
		t.Fatal("deleteExpiredBlock(zero Addr) = nil error, want error")
	}
}

func TestListBlocksFutureValueNotExpired(t *testing.T) {
	const now = uint64(1000 * time.Second)
	v4 := newFakeBlockMap[uint32]()
	v4.put(v4Key(t, "198.51.100.7"), now+1)
	v4.put(v4Key(t, "198.51.100.8"), now-uint64(2*time.Minute))

	infos, err := listBlocks(v4, v4KeyAddr, now, time.Minute)
	if err != nil {
		t.Fatalf("listBlocks: %v", err)
	}
	want := []BlockedIPInfo{
		{IP: "198.51.100.7", RemainingTTL: "1m0s"},
		{IP: "198.51.100.8", RemainingTTL: "expired"},
	}
	if len(infos) != len(want) || infos[0] != want[0] || infos[1] != want[1] {
		t.Fatalf("infos = %v, want %v", infos, want)
	}
}

func TestListBlocksReturnsIteratorError(t *testing.T) {
	iterErr := errors.New("iteration aborted")
	v6 := newFakeBlockMap[[16]byte]()
	v6.iterErr = iterErr

	if _, err := listBlocks(v6, v6KeyAddr, 1, time.Minute); !errors.Is(err, iterErr) {
		t.Fatalf("err = %v, want %v", err, iterErr)
	}
}

func TestNonPositiveBlockDurationIsPermanent(t *testing.T) {
	const now = uint64(1000 * time.Second)
	for _, duration := range []time.Duration{0, -time.Minute} {
		t.Run(duration.String(), func(t *testing.T) {
			v4 := newFakeBlockMap[uint32]()
			v4.put(v4Key(t, "198.51.100.7"), 1)
			v4.put(v4Key(t, "198.51.100.8"), now+5)
			v6 := newFakeBlockMap[[16]byte]()
			v6.put(netip.MustParseAddr("2001:db8::1").As16(), 1)

			expired, err := collectExpiredBlocks(v4, v6, fixedClock(now), duration)
			if err != nil {
				t.Fatalf("collectExpiredBlocks: %v", err)
			}
			if len(expired) != 0 {
				t.Fatalf("expired = %v, want none", expired)
			}

			infos, err := listBlocks(v4, v4KeyAddr, now, duration)
			if err != nil {
				t.Fatalf("listBlocks: %v", err)
			}
			for _, info := range infos {
				if info.RemainingTTL != "permanent" {
					t.Fatalf("RemainingTTL for %s = %q, want permanent", info.IP, info.RemainingTTL)
				}
			}
		})
	}
}
