# Fork fixture data

`python315-tailcall.tar` contains the compressed module-store blobs referenced
by the `amd64/python3.15-tailcall.json` coredump fixture, a synthetic workload
on Astral's tail-call-enabled CPython 3.15 build. The blobs are bundled because
this fork cannot publish test data to the upstream project's module store.

`make test` installs them. Before running coredump tests directly, run
`make fork-test-fixtures`. The archive expands into the ignored
`tools/coredump/modulecache` directory.
