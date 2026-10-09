# Alloy integration in this fork

The fork follows upstream OpenTelemetry `main` and adds Python 3.15 thread-state
lookup, CPython tail-call interpreter ranges, and Grafana's Alloy adapter APIs.
The adapter is based on Grafana's `pyroscope_alloy` branch at `e6edc75a` and
preserves Alloy's target policy and Python stack behavior.

## Supported deployment

The production target is Linux AMD64 with Astral CPython 3.15.0, including its
tail-call interpreter. Coredump fixtures also cover the Deadsnakes executable
and shared-library builds. Both AMD64 and ARM64 eBPF objects are generated;
ARM64 runtime support has not been validated on a live host. Dynamically
allocated ARM64 TLSDESC thread-state storage remains unsupported.

The Alloy adapter currently supports on-CPU profiling. Its legacy off-CPU and
custom-probe settings are rejected explicitly: upstream has moved those
features to collector probe extensions. The production Alloy configuration
does not enable those settings.

## Build the existing Alloy source against this fork

Use Alloy commit `041d2911a30a53f2c9c0317333aedee108a56b0a`, the source version
used by the existing deployment. Place its checkout beside this repository,
with this repository named `opentelemetry-ebpf-profiler`:

```sh
cd ../alloy
git apply ../opentelemetry-ebpf-profiler/pyroscope/alloy-compat.patch
cp ../opentelemetry-ebpf-profiler/pyroscope/alloy.go.work go.work
GOMAXPROCS=8 go test -p=8 -tags=nodocker,promtail_journal_enabled,netgo \
  ./internal/component/pyroscope/ebpf/... ./internal/component/loki/source/journal/...
GOMAXPROCS=8 SKIP_UI_BUILD=1 SKIP_CODE_GENERATION=1 RELEASE_BUILD=1 \
  GO_TAGS='netgo promtail_journal_enabled' GO_FLAGS='-v -p=8' make alloy
```

The patch updates Alloy's process-file access and its test double for the
current upstream interfaces. The workspace file pins compatible dependency
versions without changing Alloy's generated module files. In particular,
Alloy still uses the pre-stable OpenTelemetry logging API, while the profiler
needs the newer attribute API. The SDK stays on Alloy's original version to
keep resource schema URLs consistent at startup.

The build requires Alloy's normal build dependencies, `libsystemd-dev`, and
generated UI assets. `promtail_journal_enabled` is required for journal log
shipping; without it the journal component is a stub despite passing the
configuration and readiness checks. Keep `CGO_ENABLED=1` for journal support.
If the checkout has no generated UI assets, omit `SKIP_UI_BUILD=1` and install
the UI build dependencies documented by Alloy.

Before activating a build, validate the real Alloy configuration, run a
separate profiling canary on the target kernel, and verify Python frames in
the ingested CPU profiles. Keep the previous binary and systemd drop-in for
rollback; restart only Alloy.

## Tests

```sh
make test
make lint
```

`make test` installs the bundled Python 3.15 coredump fixtures. To run those
tests directly, first run `make fork-test-fixtures`; the new module-store
blobs are not published in upstream's S3 bucket.
