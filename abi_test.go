package main

import (
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestPluginABI_RegisterAndInterceptLifecycle(t *testing.T) {
	activePolicy = newRequestPolicyPlugin()
	registerRequest, err := json.Marshal(lifecycleRequest{
		ConfigYAML:    []byte(validPolicyConfig),
		SchemaVersion: pluginabi.SchemaVersion,
	})
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}
	registerRaw, err := handleMethod(pluginabi.MethodPluginRegister, registerRequest)
	if err != nil {
		t.Fatalf("handle register: %v", err)
	}
	var registerEnvelope rpcEnvelope
	if err := json.Unmarshal(registerRaw, &registerEnvelope); err != nil {
		t.Fatalf("unmarshal register envelope: %v", err)
	}
	var gotRegistration registration
	if err := json.Unmarshal(registerEnvelope.Result, &gotRegistration); err != nil {
		t.Fatalf("unmarshal registration: %v", err)
	}
	if !registerEnvelope.OK || gotRegistration.SchemaVersion != 3 || !gotRegistration.Capabilities.RequestInterceptor {
		t.Fatalf("registration = %s, want schema 3 request interceptor", registerRaw)
	}

	beforeRaw := mustMarshalRequest(t, pluginapi.RequestInterceptRequest{
		RequestedModel: "muse-spark-1.2-contributor",
		Model:          "muse-spark-1.2-contributor",
		SourceFormat:   "openai",
	})
	beforeResponse := callInterceptMethod(t, pluginabi.MethodRequestInterceptBefore, beforeRaw)
	if len(beforeResponse.Headers) != 0 || len(beforeResponse.Body) != 0 || beforeResponse.Terminate {
		t.Fatalf("before-auth response = %+v, want no-op", beforeResponse)
	}

	afterRaw := mustMarshalRequest(t, pluginapi.RequestInterceptRequest{
		RequestedModel: "muse-spark-1.2-contributor",
		Model:          "muse-spark-1.2-contributor-free",
		SourceFormat:   "openai-response",
		ToFormat:       "codex",
		Body:           []byte(`{"input":"sensitive"}`),
	})
	afterResponse := callInterceptMethod(t, pluginabi.MethodRequestInterceptAfter, afterRaw)
	if got := afterResponse.Headers.Get("X-OpenAI-Internal-Codex-Responses-Lite"); got != "true" {
		t.Fatalf("after-auth Responses-lite header = %q, want true", got)
	}
	if len(afterResponse.Body) != 0 || afterResponse.Terminate {
		t.Fatalf("after-auth response = %+v, want headers-only non-terminating response", afterResponse)
	}

	shutdownRaw, err := handleMethod(pluginabi.MethodPluginShutdown, nil)
	if err != nil {
		t.Fatalf("handle shutdown: %v", err)
	}
	var shutdownEnvelope rpcEnvelope
	if err := json.Unmarshal(shutdownRaw, &shutdownEnvelope); err != nil {
		t.Fatalf("unmarshal shutdown envelope: %v", err)
	}
	if !shutdownEnvelope.OK {
		t.Fatalf("shutdown response = %s, want ok", shutdownRaw)
	}
}

func TestPluginABI_ReconfigureRejectsInvalidConfigAndPreservesPolicy(t *testing.T) {
	activePolicy = newRequestPolicyPlugin()
	validRequest, err := json.Marshal(lifecycleRequest{ConfigYAML: []byte(validPolicyConfig), SchemaVersion: 3})
	if err != nil {
		t.Fatalf("marshal valid request: %v", err)
	}
	if _, err := handleMethod(pluginabi.MethodPluginReconfigure, validRequest); err != nil {
		t.Fatalf("valid reconfigure: %v", err)
	}

	invalidRequest, err := json.Marshal(lifecycleRequest{
		ConfigYAML:    []byte("rules:\n  muse:\n    source-formats: [unknown]\n    target-format: codex\n    set-headers: {X-Safe: value}\n"),
		SchemaVersion: 3,
	})
	if err != nil {
		t.Fatalf("marshal invalid request: %v", err)
	}
	if _, err := handleMethod(pluginabi.MethodPluginReconfigure, invalidRequest); err == nil {
		t.Fatal("invalid reconfigure error = nil, want rejection")
	}

	afterRaw := mustMarshalRequest(t, pluginapi.RequestInterceptRequest{
		RequestedModel: "muse-spark-1.2-contributor",
		Model:          "muse-spark-1.2-contributor",
		SourceFormat:   "openai",
		ToFormat:       "codex",
	})
	response := callInterceptMethod(t, pluginabi.MethodRequestInterceptAfter, afterRaw)
	if got := response.Headers.Get("X-OpenAI-Internal-Codex-Responses-Lite"); got != "true" {
		t.Fatalf("Responses-lite header after rejected reconfigure = %q, want true", got)
	}
}

func mustMarshalRequest(t *testing.T, request pluginapi.RequestInterceptRequest) []byte {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return raw
}

func callInterceptMethod(t *testing.T, method string, request []byte) pluginapi.RequestInterceptResponse {
	t.Helper()
	raw, err := handleMethod(method, request)
	if err != nil {
		t.Fatalf("handle %s: %v", method, err)
	}
	var envelope rpcEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal %s envelope: %v", method, err)
	}
	var response pluginapi.RequestInterceptResponse
	if err := json.Unmarshal(envelope.Result, &response); err != nil {
		t.Fatalf("unmarshal %s response: %v", method, err)
	}
	if !envelope.OK {
		t.Fatalf("%s response = %s, want ok", method, raw)
	}
	return response
}
