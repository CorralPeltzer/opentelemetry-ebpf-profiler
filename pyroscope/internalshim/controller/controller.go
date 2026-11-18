// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

// Package controller provides the profiler API that Alloy's pyroscope.ebpf
// component is written against.
package controller // import "go.opentelemetry.io/ebpf-profiler/pyroscope/internalshim/controller"

import (
	"errors"
	"log/slog"

	"go.opentelemetry.io/ebpf-profiler/collector"
	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/log"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/dynamicprofiling"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/internal/controller"
)

type Controller struct {
	*controller.Controller
}

type Config struct {
	*controller.Config
}

// ParseArgs returns the profiler's default configuration, which Alloy adjusts
// from its component arguments.
func ParseArgs() (*controller.Config, error) {
	cfg, ok := collector.NewFactory().CreateDefaultConfig().(*config.Config)
	if !ok {
		return nil, errors.New("unexpected default profiler configuration type")
	}
	return &controller.Config{Config: *cfg, Policy: dynamicprofiling.AlwaysOnPolicy{}}, nil
}

func New(cfg *Config) *Controller {
	if cfg.VerboseMode {
		log.SetLevel(slog.LevelDebug)
	}
	return &Controller{Controller: controller.New(cfg.Config)}
}
