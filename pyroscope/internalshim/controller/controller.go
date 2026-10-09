package controller // import "go.opentelemetry.io/ebpf-profiler/pyroscope/internalshim/controller"

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/interpreter/ruby"
	"go.opentelemetry.io/ebpf-profiler/log"
)

type Controller struct {
	*controller.Controller
	cfg *Config
}

func (c *Controller) Start(ctx context.Context) error {
	if err := c.cfg.Validate(); err != nil {
		return err
	}
	// Translate the alloy-facing ruby.ReturnToNative knob into the upstream
	// config just before the tracer loads the eBPF programs, where it is
	// applied as the ruby_skip_native_resume rodata variable.
	c.cfg.Interpreters.Ruby.SkipNativeResume = !ruby.ReturnToNative.Load()
	return c.Controller.Start(ctx)
}

type Config struct {
	*controller.Config
	OffCPUThreshold float64
	ProbeLinks      []string
	LoadProbe       bool
}

func (cfg *Config) Validate() error {
	if cfg.OffCPUThreshold != 0 || len(cfg.ProbeLinks) != 0 || cfg.LoadProbe {
		return fmt.Errorf("this Alloy adapter supports CPU profiling; custom and off-CPU probes require the upstream collector probe extensions")
	}
	return cfg.Config.Validate()
}

func New(cfg *Config) *Controller {
	// set debugging logging if requested; this is otherwise done in main.go
	if cfg.VerboseMode {
		log.SetLevel(slog.LevelDebug)
	}

	return &Controller{
		Controller: controller.New(cfg.Config),
		cfg:        cfg,
	}
}
