// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Link with libpython3.15.so.1.0 to exercise the shared-library TLS path.
// Run with PYTHONHOME set to the matching Python installation prefix.
extern int Py_BytesMain(int argc, char **argv);

int main(int argc, char **argv) { return Py_BytesMain(argc, argv); }
