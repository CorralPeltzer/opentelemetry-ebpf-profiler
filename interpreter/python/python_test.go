// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/util"
)

func TestTailCallInterpreterRange(t *testing.T) {
	tests := map[string]struct {
		sym      libpf.Symbol
		expected util.Range
		ok       bool
	}{
		"handler": {
			sym:      libpf.Symbol{Name: "_TAIL_CALL_LOAD_FAST", Address: 0x1000, Size: 0x80},
			expected: util.Range{Start: 0x1000, End: 0x1080},
			ok:       true,
		},
		"cold handler": {
			sym:      libpf.Symbol{Name: "_TAIL_CALL_LOAD_FAST.cold", Address: 0x2000, Size: 0x20},
			expected: util.Range{Start: 0x2000, End: 0x2020},
			ok:       true,
		},
		"unrelated symbol": {
			sym: libpf.Symbol{Name: "_PyEval_EvalFrameDefault", Address: 0x3000, Size: 0x100},
		},
		"zero-sized handler": {
			sym: libpf.Symbol{Name: "_TAIL_CALL_LOAD_FAST", Address: 0x4000},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			codeRange, ok := tailCallInterpreterRange(test.sym)
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.expected, codeRange)
		})
	}
}

func TestValidateMaxValue(t *testing.T) {
	type testStruct struct {
		Sizeof uint `maxValue:"4096"`
		Plain  uint
	}
	structType := reflect.TypeFor[testStruct]()

	cases := []struct {
		name      string
		fieldName string
		value     uint64
		wantSizeE bool
	}{
		{"oversized 1GiB", "Sizeof", 1 << 30, true},
		{"zero", "Sizeof", 0, true},
		{"just over cap", "Sizeof", 4096 + 1, true},
		{"at cap", "Sizeof", 4096, false},
		{"nominal", "Sizeof", 224, false},
		{"untagged", "Plain", 1 << 40, false},
		{"missing field", "Nope", 123, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMaxValue(structType, tc.fieldName, tc.value)
			assert.Equal(t, tc.wantSizeE, err != nil, "err: %v", err)
		})
	}
}

func TestFrozenNameToFileName(t *testing.T) {
	tests := map[string]struct {
		frozen    string
		expect    string
		expectErr bool
	}{
		"Frozen": {
			frozen: "<frozen _bootstrap>",
			expect: "_bootstrap.py",
		},
		"Frozen subdir": {
			frozen: "<frozen importlib._bootstrap>",
			expect: "_bootstrap.py",
		},
		"Frozen broken": {
			frozen:    "<frozen _bootstrap",
			expectErr: true,
		},
		"Frozen empty": {
			frozen:    "<frozen >",
			expectErr: true,
		},
		"empty": {
			frozen: "",
			expect: "",
		},
	}

	for name, testcase := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := frozenNameToFileName(testcase.frozen)

			if (err != nil) != testcase.expectErr {
				t.Fatalf("Unexpected error return")
			}

			if out != testcase.expect {
				t.Fatalf("'%s' does not match expected output '%s'", out, testcase.expect)
			}
		})
	}
}

func TestPythonRegexs(t *testing.T) {
	shouldMatch := map[*regexp.Regexp][]string{
		pythonRegex: {
			"python3.6", "./python3.6", "/foo/bar/python3.6", "./foo/bar/python3.6",
			"python3.7", "./python3.7", "/foo/bar/python3.7", "./foo/bar/python3.7"},
		libpythonRegex: {
			"libpython3.6", "./libpython3.6", "/foo/bar/libpython3.6",
			"./foo/bar/libpython3.6", "/foo/bar/libpython3.6.so.1",
			"/usr/lib64/libpython3.6m.so.1.0",
			"libpython3.7", "./libpython3.7", "/foo/bar/libpython3.7",
			"./foo/bar/libpython3.7", "/foo/bar/libpython3.7.so.1",
			"/foo/bar/libpython3.7m.so.1"},
	}

	for regex, strings := range shouldMatch {
		for _, s := range strings {
			assert.Truef(t, regex.MatchString(s),
				"%s should match: %v", regex.String(), s)
		}
	}

	shouldNotMatch := map[*regexp.Regexp][]string{
		pythonRegex: {
			"foopython3.6", "pyt hon3.6", "pyth/on3.6", "python",
			"foopython3.7", "pyt hon3.7", "pyth/on3.7", "python"},
		libpythonRegex: {
			"foolibpython3.6", "lib python3.6", "lib/python3.6",
			"foolibpython3.7", "lib python3.7", "lib/python3.7"},
	}

	for regex, strings := range shouldNotMatch {
		for _, s := range strings {
			assert.Falsef(t, regex.MatchString(s),
				"%v should not match: %v", regex.String(), s)
		}
	}
}
