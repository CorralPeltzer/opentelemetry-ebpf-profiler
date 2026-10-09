// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestDecodeTLSAMD64(t *testing.T) {
	// Deadsnakes libpython3.15.so.1.0, GCC 15.2, Ubuntu 26.04.
	// lea 0x41b3b1(%rip), %rdi; call __tls_get_addr; mov 8(%rax), %rax; ret.
	code, err := hex.DecodeString("f30f1efa554889e5488d3db1b34100e8bc2bd8ff5d488b8008000000c3")
	require.NoError(t, err)
	address, offset, err := decodeTLSAMD64(code, 0x3353f0)
	require.NoError(t, err)
	require.Equal(t, uint64(0x7507b0), address)
	require.Equal(t, uint64(8), offset)

	// General dynamic TLS: the index contains the variable offset, so the
	// returned pointer is dereferenced without an additional displacement.
	general := append(bytes.Clone(code[:20]), 0x48, 0x8b, 0x00, 0xc3)
	_, offset, err = decodeTLSAMD64(general, 0x3353f0)
	require.NoError(t, err)
	require.Zero(t, offset)

	for _, invalid := range [][]byte{
		nil,
		code[:len(code)-1],                   // Missing return.
		{0xc3},                               // No resolver call.
		append(bytes.Clone(code[:20]), 0xc3), // Returns the block, not its contents.
		append(bytes.Clone(code[:20]), 0xe8, 0, 0, 0, 0, 0xc3), // Second call.
	} {
		_, _, err = decodeTLSAMD64(invalid, 0x3353f0)
		require.Error(t, err)
	}
}

func TestDecodeTLSARM64(t *testing.T) {
	// Same Deadsnakes release on arm64. MRS x1, TPIDR_EL0; resolve the
	// TLSDESC at 0x781180; LDR x0, [x1, x0]; RET.
	code, err := hex.DecodeString(
		"3f2303d541d03bd5fd7bbfa9fd0300914022009002c040f900000691" +
			"40003fd6206860f8fd7bc1a8bf2303d5c0035fd6")
	require.NoError(t, err)
	address, err := decodeTLSARM64(code, 0x339524)
	require.NoError(t, err)
	require.Equal(t, uint64(0x781180), address)
	for _, invalid := range [][]byte{nil, code[:len(code)-4], {0xc0, 0x03, 0x5f, 0xd6}} {
		_, err = decodeTLSARM64(invalid, 0x339524)
		require.Error(t, err)
	}
}

func TestResolveSharedTLS(t *testing.T) {
	cases := []struct {
		name       string
		kind       pfelf.RelocType
		word0      uint64
		word1      uint64
		disp       uint64
		wantOffset int64
		wantModule uint32
		wantError  bool
	}{
		{"local dynamic", pfelf.RelDTPMOD64, 3, 0, 8, 8, 3, false},
		{"general dynamic", pfelf.RelDTPMOD64, 7, 24, 0, 24, 7, false},
		{"unresolved module", pfelf.RelDTPMOD64, 0, 0, 8, 0, 0, true},
		{"oversized module", pfelf.RelDTPMOD64, 1 << 32, 0, 8, 0, 0, true},
		{"offset overflow", pfelf.RelDTPMOD64, 1, ^uint64(0), 8, 0, 0, true},
		{"displacement overflow", pfelf.RelDTPMOD64, 1, 0, ^uint64(0), 0, 0, true},
		{"static descriptor", pfelf.RelTLSDESC, 16, 48, 0, 48, 0, false},
		{"negative descriptor", pfelf.RelTLSDESC, 16, ^uint64(39), 0, -40, 0, false},
		{"zero descriptor", pfelf.RelTLSDESC, 16, 0, 0, 0, 0, false},
		{"unknown resolver", pfelf.RelTLSDESC, 0, 48, 0, 0, 0, true},
		{"dynamic descriptor", pfelf.RelTLSDESC, 0, 0x7fff12340000, 0, 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			memory := make([]byte, 64)
			copy(memory[16:], []byte{0x5f, 0x24, 0x03, 0xd5, 0x00, 0x04, 0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6})
			binary.LittleEndian.PutUint64(memory[48:], tc.word0)
			binary.LittleEndian.PutUint64(memory[56:], tc.word1)
			tls := pythonSharedTLS{address: 16, kind: tc.kind, offset: tc.disp}
			rm := remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)}
			offset, module, err := tls.resolve(rm, 32)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantOffset, offset)
			require.Equal(t, tc.wantModule, module)
		})
	}
	tls := pythonSharedTLS{address: 16, kind: pfelf.RelDTPMOD64}
	_, _, err := tls.resolve(remotememory.RemoteMemory{ReaderAt: bytes.NewReader(nil)}, 0)
	require.Error(t, err)
}

type pythonTestEbpfHandler struct {
	interpreter.EbpfHandler
	updates []support.PyProcInfo
}

func (h *pythonTestEbpfHandler) UpdateProcData(_ libpf.InterpreterType, _ libpf.PID,
	data unsafe.Pointer,
) error {
	h.updates = append(h.updates, *(*support.PyProcInfo)(data))
	return nil
}

func TestPythonTLSLibcInfo(t *testing.T) {
	tsd := libc.LibcInfo{TSDInfo: libc.TSDInfo{Multiplier: 16, KeyLimit: 32}}
	dtv := libc.LibcInfo{DTVInfo: libc.DTVInfo{Offset: 8, Multiplier: 16}}

	// DTV may arrive later than TSD. Do not insert incomplete data or insert twice.
	p := &pythonInstance{d: &pythonData{version: pythonVer(3, 15)}, tlsModuleID: 3, tlsOffset: 8}
	h := &pythonTestEbpfHandler{}
	require.NoError(t, p.UpdateLibcInfo(h, 1, tsd))
	require.Empty(t, h.updates)
	require.NoError(t, p.UpdateLibcInfo(h, 1, dtv))
	require.NoError(t, p.UpdateLibcInfo(h, 1, dtv))
	require.Len(t, h.updates, 1)
	require.Equal(t, uint32(3), h.updates[0].Tls_module_id)
	require.Equal(t, int64(8), h.updates[0].Tls_offset)
	require.Equal(t, dtv.DTVInfo, h.updates[0].DtvInfo)

	// Zero is a valid TP-relative offset for a 3.15 TLS descriptor.
	p = &pythonInstance{d: &pythonData{version: pythonVer(3, 15)}}
	h = &pythonTestEbpfHandler{}
	require.NoError(t, p.UpdateLibcInfo(h, 1, libc.LibcInfo{}))
	require.Len(t, h.updates, 1)

	// Earlier versions still wait for their pthread fallback's TSD metadata.
	p = &pythonInstance{d: &pythonData{version: pythonVer(3, 14)}}
	h = &pythonTestEbpfHandler{}
	require.NoError(t, p.UpdateLibcInfo(h, 1, dtv))
	require.Empty(t, h.updates)
	require.NoError(t, p.UpdateLibcInfo(h, 1, tsd))
	require.Len(t, h.updates, 1)
}
