// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseArgsDefaultsValidate(t *testing.T) {
	args, err := ParseArgs()
	require.NoError(t, err)
	require.NoError(t, args.Validate())
}

func TestUnsupportedProbeSettingsAreRejected(t *testing.T) {
	for _, configure := range []func(*Config){
		func(cfg *Config) { cfg.OffCPUThreshold = 0.5 },
		func(cfg *Config) { cfg.ProbeLinks = []string{"kprobe:do_sys_open"} },
		func(cfg *Config) { cfg.LoadProbe = true },
	} {
		args, err := ParseArgs()
		require.NoError(t, err)
		cfg := &Config{Config: args}
		require.NoError(t, cfg.Validate())
		configure(cfg)
		require.ErrorContains(t, cfg.Validate(), "probe extensions")
	}
}
