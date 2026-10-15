package ebpf

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// TestTypesMatchCLayout pins the size and field offsets of the Go mirrors in
// types.go to the C structs in c/protector.bpf.c. These structs are map
// keys/values and perf event payloads shared with the kernel, so any drift
// silently corrupts reads and writes. If a C struct changes, update the Go
// mirror and this table together.
func TestTypesMatchCLayout(t *testing.T) {
	tests := []struct {
		cName   string
		value   any
		size    uintptr
		offsets []uintptr // per Go field, in declaration order
	}{
		{"tcp_session_key", TcpSessionKey{}, 12, []uintptr{0, 4, 8, 10}},
		{"tcp_session_key_v6", TcpSessionKeyV6{}, 36, []uintptr{0, 16, 32, 34}},
		{"handshake_status", HandshakeStatusGeneric{}, 24, []uintptr{0, 8, 16, 17}},
		{"rate_limit", ICMPRate{}, 24, []uintptr{0, 8, 16, 17}},
		{"bad_flags_info", BadFlagsInfo{}, 16, []uintptr{0, 8, 12}},
		{"incident_event", IncidentEvent{}, 32, []uintptr{0, 8, 12, 28, 29, 30}},
		{"event_metadata", EventMetadata{}, 56, []uintptr{
			0, 16, 20, 24, 28, 32, // saddr_v6, saddr_v4, rtt_us, seq, ts_val, ts_ecr
			36, 38, 40, 42, 44, // sport, dport, window, len, mss
			46, 47, 48, 49, 50, 51, 52, 53, // protocol .. entropy_score
		}},
	}

	for _, tt := range tests {
		t.Run(tt.cName, func(t *testing.T) {
			typ := reflect.TypeOf(tt.value)
			if got := typ.Size(); got != tt.size {
				t.Errorf("sizeof(%s) = %d, want %d (struct %s)", typ.Name(), got, tt.size, tt.cName)
			}
			if typ.NumField() != len(tt.offsets) {
				t.Fatalf("%s has %d fields, want %d (struct %s)", typ.Name(), typ.NumField(), len(tt.offsets), tt.cName)
			}
			var packed uintptr
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				if f.Offset != tt.offsets[i] {
					t.Errorf("offsetof(%s.%s) = %d, want %d (struct %s)", typ.Name(), f.Name, f.Offset, tt.offsets[i], tt.cName)
				}
				// No compiler-inserted padding between fields, so a
				// sequential binary.Read decodes the same bytes the kernel
				// wrote.
				if f.Offset != packed {
					t.Errorf("%s.%s at offset %d follows implicit padding (packed offset %d)", typ.Name(), f.Name, f.Offset, packed)
				}
				packed = f.Offset + f.Type.Size()
			}
			if got := binary.Size(tt.value); got != int(packed) {
				t.Errorf("binary.Size(%s) = %d, want %d", typ.Name(), got, packed)
			}
		})
	}
}
