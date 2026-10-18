// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

func assertBlockRequestID(t *testing.T, h http.Header) string {
	t.Helper()
	id := h.Get(blockreason.HeaderRequestID)
	if !receiptcontent.ValidRequestID(id) || id == "req-999" {
		t.Fatalf("block did not use its own request ID: %q", id)
	}
	if got := h.Get(blockreason.HeaderOperator); got != "pipelock explain event "+id {
		t.Fatalf("operator command = %q for ID %q", got, id)
	}
	if h.Get(blockreason.HeaderVersion) != "1" {
		t.Fatalf("schema changed: %v", h)
	}
	return id
}

func TestBlockReasonRequestIDScannerUnavailableTransports(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportConnect, TransportForward, TransportWS} {
		t.Run(transport, func(t *testing.T) {
			p, dir, closeRec := scannerUnavailableProxy(t)
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/resource", nil)
			r.Header.Set(blockreason.HeaderRequestID, "req-999")
			r.Header.Set(blockreason.HeaderOperator, "client command")
			w := httptest.NewRecorder()
			switch transport {
			case TransportFetch:
				p.handleFetch(w, r)
			case TransportConnect:
				r.Method = http.MethodConnect
				p.handleConnect(w, r)
			case TransportForward:
				p.handleForwardHTTP(w, r)
			case TransportWS:
				p.handleWebSocket(w, r)
			}
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", w.Code)
			}
			id := assertBlockRequestID(t, w.Result().Header)
			closeRec()
			got := findReceiptByLayer(t, extractReceiptsFromDir(t, dir), scannerLabelUnavailable)
			if got.ActionRecord.RequestID != id {
				t.Fatalf("receipt ID = %q, header ID = %q", got.ActionRecord.RequestID, id)
			}
		})
	}
}

func TestKillSwitchBlockReasonRequestIDMatchesAuditAndReceipt(t *testing.T) {
	for _, target := range []string{"/fetch?url=https://api.vendor.example/resource", "http://api.vendor.example/resource", "/ws?url=wss://api.vendor.example/chat"} {
		t.Run(target, func(t *testing.T) {
			p, dir, closeRec := scannerUnavailableProxy(t)
			var logs bytes.Buffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			p.logger = logger
			p.ks = killswitch.New(p.CurrentConfig())
			p.ks.SetAPI(true)
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			r.Header.Set(blockreason.HeaderRequestID, "req-999")
			// This path must use the newly recorded ID even if a context ID exists.
			r = r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, "req-888"))
			w := httptest.NewRecorder()
			p.buildHandler(http.NewServeMux()).ServeHTTP(w, r)
			id := assertBlockRequestID(t, w.Result().Header)
			if id == "req-888" {
				t.Fatal("kill-switch response used an unrecorded context ID")
			}
			var event map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &event); err != nil {
				t.Fatalf("audit event: %v: %s", err, logs.Bytes())
			}
			if event["event"] != "kill_switch_deny" || event["request_id"] != id {
				t.Fatalf("audit event = %v, header ID = %q", event, id)
			}
			closeRec()
			if r.URL.IsAbs() {
				if w.Code != http.StatusForbidden {
					t.Fatalf("absolute-URI status = %d, want 403", w.Code)
				}
				got := findReceiptByLayer(t, extractReceiptsFromDir(t, dir), "kill_switch")
				if got.ActionRecord.RequestID != id {
					t.Fatalf("receipt ID = %q, audit/header ID = %q", got.ActionRecord.RequestID, id)
				}
			} else {
				var body map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if w.Code != http.StatusServiceUnavailable || body["error"] != "kill_switch_active" {
					t.Fatalf("kill-switch response changed: status=%d body=%v", w.Code, body)
				}
			}
		})
	}
}

func TestBlockReasonRequestIDReverseResponses(t *testing.T) {
	for _, media := range []bool{false, true} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/resource", nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, "req-42"))
		resp := &http.Response{Request: r, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("body"))}
		resp.Header.Set(blockreason.HeaderRequestID, "req-999")
		info := blockInfoFor(blockreason.DLPMatch, "dlp")
		if media {
			replaceWithMediaBlockResponse(resp, "blocked", info)
		} else {
			replaceWithBlockReason(resp, "blocked", info)
		}
		if got := assertBlockRequestID(t, resp.Header); got != "req-42" {
			t.Fatalf("reverse response ID = %q", got)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}
