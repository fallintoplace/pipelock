// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import "testing"

func TestValidRequestID(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		id   string
		want bool
	}{
		{"req-0", true},
		{"req-123456789", true},
		{"req-0190a3c4-1234-7abc-89ab-0123456789ab", true},
		{NewRequestID(), true},
		{"", false},
		{"req-", false},
		{"req--1", false},
		{"req-1\n", false},
		{"req-1\r\nX-Test: value", false},
		{"https://api.vendor.example/req-1", false},
		{"client-provided-id", false},
		{"req-0190A3C4-1234-7abc-89ab-0123456789ab", false},
		{"req-0190a3c4-1234-4abc-89ab-0123456789ab", false},
		{"req-0190a3c4-1234-7abc-79ab-0123456789ab", false},
		{"req-0190a3c4-1234-7abc-89ab-0123456789abx", false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			if got := ValidRequestID(tc.id); got != tc.want {
				t.Fatalf("ValidRequestID(%q) = %t, want %t", tc.id, got, tc.want)
			}
		})
	}
}
