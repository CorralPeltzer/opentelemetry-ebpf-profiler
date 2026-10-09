# Fork fixture data

`python315.tar` contains the compressed module-store blobs referenced by the
three Python 3.15 AMD64 coredump fixtures: Deadsnakes executable and shared-library
builds, and Astral's tail-call-enabled executable. These synthetic workloads
contain no application data. The blobs are bundled because this fork cannot
publish test data to the upstream project's module store.

`make test` installs them automatically. Before running coredump tests directly,
run `make fork-test-fixtures`. The archive expands into the ignored
`tools/coredump/modulecache` directory; existing upstream fixtures continue to
use the upstream module store.
