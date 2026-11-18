// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package controller

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/pyroscope/dynamicprofiling"
)

func TestParseArgsDefaultsValidate(t *testing.T) {
	args, err := ParseArgs()
	require.NoError(t, err)
	require.NoError(t, args.Validate())
	require.Equal(t, dynamicprofiling.AlwaysOnPolicy{}, args.Policy)
}
