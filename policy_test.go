package main

import (
	"bytes"
	"net/http"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const validPolicyConfig = `rules:
  muse-spark-1.2-contributor:
    upstream-models:
      - muse-spark-1.2-contributor
      - muse-spark-1.2-contributor-free
    source-formats:
      - openai
      - openai-response
    target-format: codex
    set-headers:
      X-OpenAI-Internal-Codex-Responses-Lite: "true"
`

func TestRequestPolicy_InterceptBeforeAuthDeclinesWithoutMutation(t *testing.T) {
	plugin := newRequestPolicyPlugin()
	request := pluginapi.RequestInterceptRequest{
		RequestedModel: "muse-spark-1.2-contributor",
		Model:          "muse-spark-1.2-contributor",
		SourceFormat:   "openai",
		ToFormat:       "",
		Headers:        http.Header{"X-Existing": {"value"}},
		Body:           []byte(`{"model":"muse-spark-1.2-contributor"}`),
	}
	originalBody := append([]byte(nil), request.Body...)

	response := plugin.InterceptBeforeAuth(request)

	if len(response.Headers) != 0 || len(response.Body) != 0 || response.Terminate {
		t.Fatalf("InterceptBeforeAuth() = %+v, want empty no-op response", response)
	}
	if !bytes.Equal(request.Body, originalBody) {
		t.Fatal("InterceptBeforeAuth() mutated request body")
	}
}

func TestRequestPolicy_InterceptAfterAuthSetsMuseHeader(t *testing.T) {
	plugin := newRequestPolicyPlugin()
	if err := plugin.Reconfigure([]byte(validPolicyConfig)); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	tests := []struct {
		name          string
		upstreamModel string
		sourceFormat  string
	}{
		{name: "Go Chat Completions", upstreamModel: "muse-spark-1.2-contributor", sourceFormat: "openai"},
		{name: "Zen Responses", upstreamModel: "muse-spark-1.2-contributor-free", sourceFormat: "openai-response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := pluginapi.RequestInterceptRequest{
				RequestedModel: "muse-spark-1.2-contributor",
				Model:          test.upstreamModel,
				SourceFormat:   test.sourceFormat,
				ToFormat:       "codex",
				Headers:        http.Header{"X-Existing": {"value"}},
				Body:           []byte(`{"input":"sensitive"}`),
			}
			originalBody := append([]byte(nil), request.Body...)

			response := plugin.InterceptAfterAuth(request)

			if got := response.Headers.Get("X-OpenAI-Internal-Codex-Responses-Lite"); got != "true" {
				t.Fatalf("Responses-lite header = %q, want true", got)
			}
			if len(response.Headers) != 1 {
				t.Fatalf("response headers = %#v, want only policy header", response.Headers)
			}
			if len(response.Body) != 0 || response.Terminate {
				t.Fatalf("InterceptAfterAuth() = %+v, want headers-only non-terminating response", response)
			}
			if !bytes.Equal(request.Body, originalBody) {
				t.Fatal("InterceptAfterAuth() mutated request body")
			}
		})
	}
}

func TestRequestPolicy_InterceptAfterAuthDeclinesNonMatchingRequests(t *testing.T) {
	plugin := newRequestPolicyPlugin()
	if err := plugin.Reconfigure([]byte(validPolicyConfig)); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	tests := []struct {
		name           string
		requestedModel string
		upstreamModel  string
		sourceFormat   string
		targetFormat   string
	}{
		{name: "different alias", requestedModel: "other", upstreamModel: "muse-spark-1.2-contributor", sourceFormat: "openai", targetFormat: "codex"},
		{name: "different upstream", requestedModel: "muse-spark-1.2-contributor", upstreamModel: "other", sourceFormat: "openai", targetFormat: "codex"},
		{name: "different source", requestedModel: "muse-spark-1.2-contributor", upstreamModel: "muse-spark-1.2-contributor", sourceFormat: "claude", targetFormat: "codex"},
		{name: "different target", requestedModel: "muse-spark-1.2-contributor", upstreamModel: "muse-spark-1.2-contributor", sourceFormat: "openai", targetFormat: "openai"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := plugin.InterceptAfterAuth(pluginapi.RequestInterceptRequest{
				RequestedModel: test.requestedModel,
				Model:          test.upstreamModel,
				SourceFormat:   test.sourceFormat,
				ToFormat:       test.targetFormat,
			})
			if len(response.Headers) != 0 || len(response.Body) != 0 || response.Terminate {
				t.Fatalf("InterceptAfterAuth() = %+v, want empty no-op response", response)
			}
		})
	}
}

func TestRequestPolicy_ReconfigureRejectsUnsafeRules(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{name: "empty model", config: "rules:\n  '  ':\n    source-formats: [openai]\n    target-format: codex\n    set-headers: {X-Safe: value}\n"},
		{name: "unknown source format", config: "rules:\n  muse:\n    source-formats: [unknown]\n    target-format: codex\n    set-headers: {X-Safe: value}\n"},
		{name: "unknown target format", config: "rules:\n  muse:\n    source-formats: [openai]\n    target-format: unknown\n    set-headers: {X-Safe: value}\n"},
		{name: "empty header", config: "rules:\n  muse:\n    source-formats: [openai]\n    target-format: codex\n    set-headers: {'  ': value}\n"},
		{name: "authorization header", config: "rules:\n  muse:\n    source-formats: [openai]\n    target-format: codex\n    set-headers: {Authorization: value}\n"},
		{name: "cookie header", config: "rules:\n  muse:\n    source-formats: [openai]\n    target-format: codex\n    set-headers: {Cookie: value}\n"},
		{name: "API key header", config: "rules:\n  muse:\n    source-formats: [openai]\n    target-format: codex\n    set-headers: {X-API-Key: value}\n"},
		{name: "token header", config: "rules:\n  muse:\n    source-formats: [openai]\n    target-format: codex\n    set-headers: {X-Auth-Token: value}\n"},
		{name: "secret header", config: "rules:\n  muse:\n    source-formats: [openai]\n    target-format: codex\n    set-headers: {X-Client-Secret: value}\n"},
		{name: "CRLF header value", config: "rules:\n  muse:\n    source-formats: [openai]\n    target-format: codex\n    set-headers:\n      X-Safe: |\n        value\r\n        injected\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plugin := newRequestPolicyPlugin()
			if err := plugin.Reconfigure([]byte(test.config)); err == nil {
				t.Fatal("Reconfigure() error = nil, want unsafe rule rejection")
			}
		})
	}
}

func TestRequestPolicy_ReconfigurePreservesValidSnapshotAfterRejection(t *testing.T) {
	plugin := newRequestPolicyPlugin()
	if err := plugin.Reconfigure([]byte(validPolicyConfig)); err != nil {
		t.Fatalf("initial Reconfigure() error = %v", err)
	}
	if err := plugin.Reconfigure([]byte("rules:\n  muse:\n    source-formats: [unknown]\n    target-format: codex\n    set-headers: {X-Safe: value}\n")); err == nil {
		t.Fatal("invalid Reconfigure() error = nil, want rejection")
	}

	response := plugin.InterceptAfterAuth(pluginapi.RequestInterceptRequest{
		RequestedModel: "muse-spark-1.2-contributor",
		Model:          "muse-spark-1.2-contributor",
		SourceFormat:   "openai",
		ToFormat:       "codex",
	})
	if got := response.Headers.Get("X-OpenAI-Internal-Codex-Responses-Lite"); got != "true" {
		t.Fatalf("Responses-lite header after rejected update = %q, want true", got)
	}
}

func TestRequestPolicy_ConcurrentInterceptsUseValidSnapshot(t *testing.T) {
	plugin := newRequestPolicyPlugin()
	if err := plugin.Reconfigure([]byte(validPolicyConfig)); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	const calls = 100
	responses := make(chan pluginapi.RequestInterceptResponse, calls)
	var wait sync.WaitGroup
	for range calls {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- plugin.InterceptAfterAuth(pluginapi.RequestInterceptRequest{
				RequestedModel: "muse-spark-1.2-contributor",
				Model:          "muse-spark-1.2-contributor",
				SourceFormat:   "openai",
				ToFormat:       "codex",
			})
		}()
	}
	wait.Wait()
	close(responses)

	for response := range responses {
		if got := response.Headers.Get("X-OpenAI-Internal-Codex-Responses-Lite"); got != "true" {
			t.Fatalf("Responses-lite header = %q, want true", got)
		}
	}
}
