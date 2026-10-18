// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package blockreason

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

func TestBlockReasonRequestIDHeaders(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"req-42", "req-0190a3c4-1234-7abc-89ab-0123456789ab", "", "https://api.vendor.example/", "client-id", "req-42\r\nX-Test: value"} {
		t.Run(id, func(t *testing.T) {
			for _, direct := range []bool{false, true} {
				info := MustNewForReason(DLPMatch).WithRequestID(id)
				if direct {
					info.RequestID = id
				}
				h := http.Header{}
				h.Set(HeaderRequestID, "stale-client-id")
				h.Set(HeaderOperator, "stale-command")
				info.SetHeaders(h)
				wantID, wantCommand := "", ""
				if receiptcontent.ValidRequestID(id) {
					wantID, wantCommand = id, "pipelock explain event "+id
				}
				if h.Get(HeaderRequestID) != wantID || h.Get(HeaderOperator) != wantCommand {
					t.Fatalf("headers = %v, want ID %q and command %q", h, wantID, wantCommand)
				}
				got, ok := FromHeader(h)
				if !ok || got.RequestID != wantID || got.Reason != DLPMatch || h.Get(HeaderVersion) != "1" {
					t.Fatalf("decoded block = %+v, ok=%t, headers=%v", got, ok, h)
				}
			}
		})
	}
	if got := MustNewForReason(DLPMatch).WithRequestID("req-42").WithRequestID("invalid"); got.RequestID != "" {
		t.Fatalf("invalid replacement retained ID %q", got.RequestID)
	}
}

func TestCloseFrameRequestIDPreservesEveryReason(t *testing.T) {
	t.Parallel()
	const id = "req-0190a3c4-1234-7abc-89ab-0123456789ab"
	for _, reason := range AllReasons() {
		info := MustNewForReason(reason).WithRequestID(id)
		payload := info.CloseFramePayload()
		var got closeFramePayload
		if err := json.Unmarshal([]byte(payload), &got); err != nil {
			t.Fatal(err)
		}
		if len(payload) > closeFrameMaxBytes || got.BlockReason != string(reason) || got.RequestID != id {
			t.Fatalf("reason %q: %d-byte payload %s", reason, len(payload), payload)
		}
	}
}

func TestCloseFrameRequestIDByteBoundary(t *testing.T) {
	t.Parallel()
	base := closeFramePayload{BlockReason: string(DLPMatch), RequestID: receiptcontent.RequestIDPrefix}
	for _, extra := range []int{0, 1} {
		id := receiptcontent.RequestIDPrefix + strings.Repeat("1", closeFrameMaxBytes-len(mustMarshal(base))+extra)
		payload := MustNewForReason(DLPMatch).WithRequestID(id).CloseFramePayload()
		var got closeFramePayload
		if err := json.Unmarshal([]byte(payload), &got); err != nil {
			t.Fatal(err)
		}
		if len(payload) > closeFrameMaxBytes || got.BlockReason != string(DLPMatch) {
			t.Fatalf("reason lost or payload oversized: %s", payload)
		}
		if (extra == 0 && (got.RequestID != id || len(payload) != closeFrameMaxBytes)) || (extra == 1 && got.RequestID != "") {
			t.Fatalf("extra=%d: %d-byte payload %s", extra, len(payload), payload)
		}
	}
	info := MustNewForReason(DLPMatch)
	info.RequestID = "https://api.vendor.example/"
	if strings.Contains(info.CloseFramePayload(), "request_id") {
		t.Fatal("invalid ID reached close frame")
	}
}
