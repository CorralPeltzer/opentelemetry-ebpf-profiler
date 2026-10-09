// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func decodeStubArgumentAMD64(
	code []byte,
	codeAddress, memBase uint64,
) (
	libpf.SymbolValue, error,
) {
	it := amd.NewInterpreterWithCodeAt(code, e.Imm(codeAddress))
	_, err := it.LoopWithBreak(func(op x86asm.Inst) bool {
		return op.Op == x86asm.JMP || op.Op == x86asm.CALL
	})
	if err != nil {
		return 0, err
	}
	answer, err := evaluateStubAnswerAMD64(it.Regs.Get(amd.RDI), memBase)
	if err != nil {
		return 0, err
	}
	return libpf.SymbolValue(answer), err
}

func evaluateStubAnswerAMD64(res e.Expression, memBase uint64) (uint64, error) {
	answer := e.NewImmediateCapture("answer")
	if res.Match(e.ZeroExtend32(e.Mem8(answer))) {
		return answer.CapturedValue(), nil
	}
	if res.Match(
		e.Add(
			e.Mem8(e.NewImmediateCapture("mem")),
			answer,
		),
	) {
		return memBase + answer.CapturedValue(), nil
	}
	if res.Match(
		e.ZeroExtend32(
			e.Mem8(
				e.Add(
					e.Mem8(e.NewImmediateCapture("mem")),
					answer,
				),
			),
		),
	) {
		return memBase + answer.CapturedValue(), nil
	}
	if res.Match(answer) {
		return answer.CapturedValue(), nil
	}
	return 0, fmt.Errorf("not found %s", res.DebugString())
}

// decodeTLSAMD64 recognizes general/local dynamic TLS in _PyThreadState_GetCurrent:
// __tls_get_addr(&tls_index), followed by a pointer load from the returned block.
func decodeTLSAMD64(code []byte, codeAddress uint64) (address, offset uint64, err error) {
	it := amd.NewInterpreterWithCodeAt(code, e.Imm(codeAddress))
	op, err := it.LoopWithBreak(func(op x86asm.Inst) bool {
		return op.Op == x86asm.CALL || op.Op == x86asm.JMP || op.Op == x86asm.RET
	})
	if err != nil {
		return 0, 0, err
	}
	address, ok := e.AsConstant(it.Regs.Get(amd.RDI))
	if op.Op != x86asm.CALL || !ok || address == 0 || address%8 != 0 {
		return 0, 0, fmt.Errorf("no TLS index argument")
	}

	// Start with fresh registers: RAX now represents the resolver's return value.
	it = amd.NewInterpreterWithCodeAt(code[it.PC():], e.Imm(codeAddress+it.PC()))
	base := it.Regs.Get(amd.RAX)
	op, err = it.LoopWithBreak(func(op x86asm.Inst) bool {
		return op.Op == x86asm.RET || op.Op == x86asm.CALL || op.Op == x86asm.JMP
	})
	if err != nil {
		return 0, 0, err
	}
	result := it.Regs.Get(amd.RAX)
	disp := e.NewImmediateCapture("offset")
	if op.Op == x86asm.RET {
		if result.Match(e.Mem8(base)) {
			return address, 0, nil
		}
		if result.Match(e.Mem8(e.Add(base, disp))) && disp.CapturedValue() < 4096 {
			return address, disp.CapturedValue(), nil
		}
	}
	return 0, 0, fmt.Errorf("no thread-state load from TLS result")
}
