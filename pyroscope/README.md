# Alloy integration in this fork

The fork follows upstream OpenTelemetry `main` and adds two things:

- CPython tail-call interpreter support (`--with-tail-call-interp`, as in
  Astral's python-build-standalone builds).
- The profiler API that Grafana Alloy's `pyroscope.ebpf` component uses:
  `pyroscope/internalshim/controller`, `pyroscope/dynamicprofiling` and
  `python.NoContinueWithNextUnwinder`. Grafana provides the same API in its
  `pyroscope_alloy` branch.

The production target is Linux AMD64 with Astral CPython 3.15. Only on-CPU
profiling has been validated; Alloy's off-CPU and probe settings reach
upstream's probe API untested.

## Build Alloy against this fork

Check out Alloy `v1.22.0` beside this repository, with this repository named
`opentelemetry-ebpf-profiler`:

```sh
cd ../alloy
git apply ../opentelemetry-ebpf-profiler/pyroscope/alloy-compat.patch
cp ../opentelemetry-ebpf-profiler/pyroscope/alloy.go.work go.work
go test -tags nodocker,promtail_journal_enabled,netgo \
  ./internal/component/pyroscope/ebpf/... ./internal/component/loki/source/journal/...
cd collector
CGO_ENABLED=1 go build -tags 'gore2regex netgo promtail_journal_enabled' \
  -ldflags '-s -w -X github.com/grafana/alloy/internal/build.Version=v1.22.0+ebpf' \
  -o ../build/alloy .
```

The patch adapts Alloy's pprof reporter and its tests to the upstream sample
and process APIs. The workspace file points Alloy at this repository.

`promtail_journal_enabled` is required for journal log shipping; without it
the journal component is a stub that still passes configuration and readiness
checks. Journal support needs Cgo and `libsystemd-dev`. The binary is built
without the embedded web UI and Beyla.

Before activating a build, validate the real Alloy configuration, run a
separate profiling canary on the target kernel, and verify Python frames in
the ingested CPU profiles. Keep the previous binary for rollback.

## Tests

```sh
make test
make lint
```

`make test` installs the tail-call coredump fixture's module-store blobs. To
run the coredump tests directly, first run `make fork-test-fixtures`.
