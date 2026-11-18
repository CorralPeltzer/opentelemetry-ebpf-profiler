// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

type testProfilingPolicy bool

func (p testProfilingPolicy) ProfilingEnabled(process.Process, string) bool {
	return bool(p)
}

func TestProfilingPolicyRetainsTrackedProcesses(t *testing.T) {
	pid := libpf.PID(0)
	pr := &testProcess{pid: pid}
	pm := &ProcessManager{
		policy:           testProfilingPolicy(false),
		pidToProcessInfo: make(map[libpf.PID]*processInfo),
	}
	require.False(t, pm.profilingEnabled(pr))
	pm.pidToProcessInfo[pid] = &processInfo{}
	require.True(t, pm.profilingEnabled(pr))
	delete(pm.pidToProcessInfo, pid)
	pm.policy = testProfilingPolicy(true)
	require.True(t, pm.profilingEnabled(pr))
}
