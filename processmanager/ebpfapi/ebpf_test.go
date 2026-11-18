// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfapi

import (
	"math/bits"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestInterpreterRangeKey(t *testing.T) {
	fileID := host.FileID(0x0102030405060708)
	prefix := lpm.Prefix{Key: 0x1112131415161718, Length: 53}

	key := InterpreterRangeKey(fileID, prefix)

	assert.Equal(t, uint32(support.BitWidthFileID)+prefix.Length, key.PrefixLen)
	assert.Equal(t, bits.ReverseBytes32(uint32(0x01020304)), key.FileIDHigh)
	assert.Equal(t, bits.ReverseBytes32(uint32(0x05060708)), key.FileIDLow)
	assert.Equal(t, bits.ReverseBytes32(uint32(0x11121314)), key.OffsetHigh)
	assert.Equal(t, bits.ReverseBytes32(uint32(0x15161718)), key.OffsetLow)
}
