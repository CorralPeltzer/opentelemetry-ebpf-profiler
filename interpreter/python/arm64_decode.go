// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"fmt"

	aa "golang.org/x/arch/arm64/arm64asm"

	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	"go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// decodeStubArgumentARM64 disassembles arm64 code and decodes the assumed value
// of requested argument.
func decodeStubArgumentARM64(code []byte,
	addrBase libpf.SymbolValue) libpf.SymbolValue {
	const argNumber uint8 = 0
	// The concept is to track the latest load offset for all X0..X30 registers.
	// These registers are used as the function arguments. Once the first branch
	// instruction (function call/tail jump) is found, the state of the requested
	// argument register's offset is inspected and returned if found.
	// It is seen often that the load with offset happens to intermediate register
	// first, and is later moved to the argument register. Because of this, the
	// tracking requires extra effort between register moves etc.

	// PyEval_ReleaseLock (Amazon Linux /usr/lib64/libpython3.7m.so.1.0):
	// ADRP X0, .+0x148000
	// LDR X1, [X0,#1960]
	// ADD X2, X1, #0x5d8		1. X2's regOffset is 0x5d8 (the value we want)
	// LDR X0, [X2]			2. The argument register is loaded via X2
	// B .+0xfffffffffffffe88

	// PyGILState_GetThisThreadState (Amazon Linux /usr/lib64/libpython3.7m.so.1.0):
	// ADRP X0, .+0x251000
	// LDR X2, [X0,#1960]
	// LDR X1, [X2,#1512]
	// CBZ X1, .+0xc
	// ADD X0, X2, #0x5f0		1. X0's regOffset gets 0x5f0
	// B .+0xfffffffffffb92b4

	// PyGILState_GetThisThreadState (Debian 11 /usr/bin/python3):
	// ADRP X0, #0x907000
	// ADD  X2, X0, #0x880
	// ADD  X3, X2, #0x10
	// LDR  X1, [X2,#0x260]
	// CBZ  X1, loc_4740BC
	// LDR  W0, [X3,#0x25C] ; key
	// B    .pthread_getspecific

	// Storage for load offsets for each Xn register
	var regOffset [32]int64
	retValue := libpf.SymbolValueInvalid

	for offs := 0; offs < len(code); offs += 4 {
		inst, err := aa.Decode(code[offs:])
		if err != nil {
			return libpf.SymbolValueInvalid
		}
		if inst.Op == aa.B {
			return retValue
		}

		// Interested only on commands modifying Xn
		dest, ok := arm.Xreg2num(inst.Args[0])
		if !ok {
			continue
		}

		instOffset := int64(0)
		instRetval := libpf.SymbolValueInvalid
		switch inst.Op {
		case aa.ADD:
			a2, ok := arm.DecodeImmediate(inst.Args[2])
			if !ok {
				break
			}
			instOffset = a2
			instRetval = addrBase + libpf.SymbolValue(a2)
		case aa.LDR:
			m, ok := inst.Args[1].(aa.MemImmediate)
			if !ok {
				break
			}
			src, ok := arm.Xreg2num(m.Base)
			if !ok {
				break
			}
			imm, ok := arm.DecodeImmediate(inst.Args[1])
			if !ok {
				break
			}
			// FIXME: addressing mode not taken into account
			// because m.imm is not public, but needed.
			instRetval = addrBase + libpf.SymbolValue(regOffset[src]+imm)
		}
		regOffset[dest] = instOffset
		if dest == int(argNumber) {
			retValue = instRetval
		}
	}

	return libpf.SymbolValueInvalid
}

// decodeTLSARM64 recognizes the TLSDESC sequence used by shared libpython builds.
// The descriptor call returns a TP-relative offset; the getter loads TP[offset].
func decodeTLSARM64(code []byte, codeAddress uint64) (uint64, error) {
	it := arm.NewInterpreterWithCodeAt(code, expression.Imm(codeAddress))
	var address uint64
	called := false
	for {
		op, err := it.Step()
		if err != nil {
			return 0, err
		}
		switch op.Op {
		case aa.MRS:
			if op.Args[1].String() == "S3_3_C13_C0_2" {
				reg, ok := op.Args[0].(aa.Reg)
				if ok {
					it.Regs.NameRegisterArm(reg, "tp")
				}
			}
		case aa.BLR:
			arg := it.Regs.Get(arm.X0)
			var ok bool
			address, ok = expression.AsConstant(arg)
			reg, regOK := op.Args[0].(aa.Reg)
			if called || !ok || address == 0 || address%8 != 0 || !regOK ||
				!it.Regs.GetArm(reg).Match(expression.Mem8(arg)) {
				return 0, fmt.Errorf("no TLS descriptor call")
			}
			called = true
			it.Regs.NameRegisterArm(aa.X0, "tls_offset")
		case aa.RET:
			want := expression.Mem8(expression.Add(
				expression.Named("tp"), expression.Named("tls_offset")))
			if called && it.Regs.Get(arm.X0).Match(want) {
				return address, nil
			}
			return 0, fmt.Errorf("no thread-state load from TLS descriptor result")
		case aa.B, aa.BL, aa.BR:
			return 0, fmt.Errorf("unexpected branch in TLS getter")
		}
	}
}
