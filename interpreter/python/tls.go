// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"math"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// pythonSharedTLS describes the relocation used to access _Py_tss_tstate.
// Resolve it separately for each process, after the dynamic linker has run.
type pythonSharedTLS struct {
	address libpf.Address
	kind    pfelf.RelocType
	offset  uint64
}

func getSharedTLSFromAssembly(ef *pfelf.File) (pythonSharedTLS, error) {
	sym, code, err := ef.SymbolData("_PyThreadState_GetCurrent", 512)
	if err != nil {
		return pythonSharedTLS{}, err
	}
	var address, offset uint64
	var kind pfelf.RelocType
	switch ef.Machine {
	case elf.EM_X86_64:
		address, offset, err = decodeTLSAMD64(code, uint64(sym.Address))
		kind = pfelf.RelDTPMOD64
	case elf.EM_AARCH64:
		address, err = decodeTLSARM64(code, uint64(sym.Address))
		kind = pfelf.RelTLSDESC
	default:
		err = fmt.Errorf("unsupported TLS architecture %s", ef.Machine)
	}
	if err != nil {
		return pythonSharedTLS{}, err
	}

	// Do not mistake an unrelated call or memory access for a TLS lookup.
	found := false
	err = ef.VisitRelocations(func(r pfelf.ElfReloc, _ string, _ pfelf.RelocType) bool {
		found = r.Off == address
		return !found
	}, kind)
	if err != nil {
		return pythonSharedTLS{}, err
	}
	if !found {
		return pythonSharedTLS{}, fmt.Errorf("no TLS relocation at 0x%x", address)
	}
	return pythonSharedTLS{address: libpf.Address(address), kind: kind, offset: offset}, nil
}

func (t pythonSharedTLS) resolve(rm remotememory.RemoteMemory,
	bias libpf.Address,
) (offset int64, moduleID uint32, err error) {
	value, err := rm.ReadUint64(bias + t.address + 8)
	if err != nil {
		return 0, 0, fmt.Errorf("read Python TLS relocation: %w", err)
	}
	switch t.kind {
	case pfelf.RelDTPMOD64:
		// tls_index contains the module ID and a module-relative offset. Local
		// dynamic TLS adds the variable's offset after __tls_get_addr returns.
		id, err := rm.ReadUint64(bias + t.address)
		if err != nil {
			return 0, 0, fmt.Errorf("read Python TLS module ID: %w", err)
		}
		if id == 0 || id > math.MaxUint32 || value > math.MaxInt32 ||
			t.offset > math.MaxInt32-value {
			return 0, 0, errors.New("invalid Python TLS index")
		}
		return int64(value + t.offset), uint32(id), nil
	case pfelf.RelTLSDESC:
		// The static TLSDESC resolver returns its second word, a signed
		// TP-relative offset. Dynamic descriptors instead contain a pointer
		// to resolver state; reject those rather than treating it as an offset.
		offset = int64(value)
		if offset < math.MinInt32 || offset > math.MaxInt32 {
			return 0, 0, errors.New("dynamic Python TLS descriptor is unsupported")
		}
		resolver, err := rm.ReadPtr(bias + t.address)
		if err != nil {
			return 0, 0, fmt.Errorf("read Python TLS resolver: %w", err)
		}
		code := make([]byte, 12)
		if err := rm.Read(resolver, code); err != nil {
			return 0, 0, fmt.Errorf("read Python TLS resolver code: %w", err)
		}
		// AArch64 glibc and musl static resolvers: [BTI c]; LDR X0,[X0,#8]; RET.
		// Checking the resolver also rejects dynamic/unresolved descriptors whose
		// argument happens to be a pointer in the low 2 GB of the address space.
		if bytes.HasPrefix(code, []byte{0x5f, 0x24, 0x03, 0xd5}) {
			code = code[4:]
		}
		if !bytes.HasPrefix(code, []byte{0x00, 0x04, 0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6}) {
			return 0, 0, errors.New("unsupported Python TLS descriptor resolver")
		}
		return offset, 0, nil
	default:
		return 0, 0, errors.New("unsupported Python TLS relocation")
	}
}
