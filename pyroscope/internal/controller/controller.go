// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

// Package controller runs the profiler for Alloy. Upstream runs it as the
// collector receiver in package collector; this package keeps the standalone
// controller that Alloy's pyroscope.ebpf component drives directly.
package controller // import "go.opentelemetry.io/ebpf-profiler/pyroscope/internal/controller"

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/internal/linux"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/dynamicprofiling"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// Config holds the profiler configuration and the components Alloy provides.
type Config struct {
	config.Config
	Policy dynamicprofiling.Policy

	ExecutableReporter reporter.ExecutableReporter
	// ProcessMetaEnrichers are optional hooks for enriching process metadata at
	// process discovery and executable change time. Multiple enrichers are called in order.
	ProcessMetaEnrichers []process.MetaEnricher
	Reporter             reporter.Reporter
}

// Validate runs validations on the provided configuration, and returns errors
// if invalid values were provided.
func (cfg *Config) Validate() error {
	return cfg.Config.Validate()
}

// Controller is an instance that runs, manages and stops the profiler.
type Controller struct {
	config   *Config
	reporter reporter.Reporter
	tracer   *tracer.Tracer

	shutdownOnceFn sync.Once
	cancelFunc     context.CancelFunc
}

// New creates a new controller. The controller can set global configurations
// (such as the eBPF syscalls) on setup, so there should only ever be one running.
func New(cfg *Config) *Controller {
	return &Controller{
		config:   cfg,
		reporter: cfg.Reporter,
	}
}

// Start loads the eBPF tracer, starts the reporter and attaches the tracer to
// the kernel. The controller should only be started once. If Start fails, the
// caller must call Shutdown to release what was set up.
func (c *Controller) Start(ctx context.Context) error {
	if err := linux.ProbeBPFSyscall(); err != nil {
		return fmt.Errorf("failed to probe eBPF syscall: %w", err)
	}

	intervals := times.New(c.config.ReporterInterval, c.config.MonitorInterval,
		c.config.ProbabilisticInterval)

	ctx, c.cancelFunc = context.WithCancel(ctx)

	// Start periodic synchronization with the realtime clock
	times.StartRealtimeSync(ctx, c.config.ClockSyncInterval)

	envVars := libpf.Set[string]{}
	for envVar := range strings.SplitSeq(c.config.IncludeEnvVars, ",") {
		envVar = strings.TrimSpace(envVar)
		if envVar != "" {
			envVars[envVar] = libpf.Void{}
		}
	}

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		Policy:                      c.config.Policy,
		TraceReporter:               c.reporter,
		Intervals:                   intervals,
		InterpretersConfig:          c.config.Interpreters,
		FilterErrorFrames:           !c.config.SendErrorFrames,
		FilterIdleFrames:            !c.config.SendIdleFrames,
		FilterMinProcessAge:         c.config.FilterMinProcessAge,
		SamplesPerSecond:            c.config.SamplesPerSecond,
		MapScaleFactor:              int(c.config.MapScaleFactor),
		FrameCacheSize:              uint32(c.config.FrameCacheSize),
		KernelVersionCheck:          !c.config.NoKernelVersionCheck,
		VerboseMode:                 c.config.VerboseMode,
		BPFVerifierLogLevel:         uint32(c.config.BPFVerifierLogLevel),
		MaxConcurrentProgLoads:      int(c.config.MaxConcurrentProgLoads),
		ProbabilisticInterval:       c.config.ProbabilisticInterval,
		ProbabilisticThreshold:      c.config.ProbabilisticThreshold,
		IncludeEnvVars:              envVars,
		ExecutableReporter:          c.config.ExecutableReporter,
		BPFFSRoot:                   c.config.BPFFSRoot,
		OBIProcessCtx:               c.config.OBIProcessCtx,
		ProcessMetaEnrichers:        c.config.ProcessMetaEnrichers,
		PIDNamespaceTranslationMode: c.config.PIDNamespaceTranslationMode,
	})
	if err != nil {
		return fmt.Errorf("failed to load eBPF tracer: %w", err)
	}
	c.tracer = trc
	log.Info("eBPF tracer loaded")

	// Wire probe snapshot sources into the reporter before starting its
	// collection loop.
	c.reporter.SetSnapshotSource(trc)

	if err := c.reporter.Start(ctx); err != nil {
		return fmt.Errorf("failed to start reporter: %w", err)
	}

	now := time.Now()

	trc.StartPIDEventProcessor(ctx)

	metrics.Add(metrics.IDProcPIDStartupMs, metrics.MetricValue(time.Since(now).Milliseconds()))
	log.Debug("Completed initial PID listing")

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(c.config.PinnedCPUIDs); err != nil {
		return fmt.Errorf("failed to attach to perf event: %w", err)
	}
	log.Info("Attached tracer program")

	if c.config.ProbabilisticThreshold < tracer.ProbabilisticThresholdMax {
		trc.StartProbabilisticProfiling(ctx)
		log.Info("Enabled probabilistic profiling")
	} else if err := trc.EnableProfiling(); err != nil {
		return fmt.Errorf("failed to enable perf events: %w", err)
	}

	if err := trc.AttachSchedMonitor(); err != nil {
		return fmt.Errorf("failed to attach scheduler monitor: %w", err)
	}
	log.Info("Attached sched monitor")

	// A missing prctl monitor only delays discovery of process context mappings;
	// core profiling is unaffected, so warn and continue rather than aborting.
	if err := trc.AttachPrctlMonitor(); err != nil {
		log.Warnf("Failed to attach prctl monitor: %v", err)
	} else {
		log.Info("Attached prctl monitor")
	}

	traceCh := make(chan *libpf.EbpfTrace)
	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %w", err)
	}

	go func() {
		for {
			select {
			case trace := <-traceCh:
				if trace != nil {
					trc.HandleTrace(trace)
				}
			case <-trc.Done():
				log.Errorf("Shutting down controller due to unrecoverable tracer error")
				c.Shutdown()
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

// Shutdown stops the reporter and the tracer. It is safe to call multiple
// times and from the trace handling goroutine.
func (c *Controller) Shutdown() {
	c.shutdownOnceFn.Do(func() {
		log.Info("Stop processing ...")
		if c.cancelFunc != nil {
			c.cancelFunc()
		}
		if c.reporter != nil {
			c.reporter.Stop()
		}
		if c.tracer != nil {
			c.tracer.Close()
		}
	})
}

// EnableProbe enables a probe on the running tracer. It must be called after
// Start has completed.
func (c *Controller) EnableProbe(ctx context.Context, p tracer.Probe) error {
	return c.tracer.Enable(ctx, p)
}
