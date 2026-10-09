// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import "sync/atomic"

// NoContinueWithNextUnwinder preserves Alloy's Python-only stack behavior.
var NoContinueWithNextUnwinder atomic.Bool

func continueWithNextUnwinder() uint8 {
	if NoContinueWithNextUnwinder.Load() {
		return 0
	}
	return 1
}
