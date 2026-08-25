package main

import (
	"encoding/json"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type rpcEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	RequestInterceptor bool `json:"request_interceptor"`
}

var activePolicy = newRequestPolicyPlugin()

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		var lifecycle lifecycleRequest
		if len(request) > 0 {
			if err := json.Unmarshal(request, &lifecycle); err != nil {
				return nil, fmt.Errorf("decode lifecycle request: %w", err)
			}
		}
		if lifecycle.SchemaVersion != 0 && lifecycle.SchemaVersion != pluginabi.SchemaVersion {
			return nil, fmt.Errorf("unsupported host schema version %d", lifecycle.SchemaVersion)
		}
		if err := activePolicy.Reconfigure(lifecycle.ConfigYAML); err != nil {
			return nil, fmt.Errorf("configure request policy: %w", err)
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodPluginShutdown:
		activePolicy.Shutdown()
		return okEnvelope(struct{}{})
	case pluginabi.MethodRequestInterceptBefore:
		return interceptRequest(request, activePolicy.InterceptBeforeAuth)
	case pluginabi.MethodRequestInterceptAfter:
		return interceptRequest(request, activePolicy.InterceptAfterAuth)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method)
	}
}

func interceptRequest(
	raw []byte,
	intercept func(pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse,
) ([]byte, error) {
	var request pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return nil, fmt.Errorf("decode request intercept: %w", err)
	}
	return okEnvelope(intercept(request))
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "Model Request Policy",
			Version:          "0.1.0",
			Author:           "abdwhb-png",
			GitHubRepository: "https://github.com/abdwhb-png/cliproxy-model-request-policy",
			ConfigFields: []pluginapi.ConfigField{{
				Name:        "rules",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Exact request policy rules that may set non-sensitive headers after auth selection.",
			}},
		},
		Capabilities: registrationCapability{RequestInterceptor: true},
	}
}

func okEnvelope(result any) ([]byte, error) {
	rawResult, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rpcEnvelope{OK: true, Result: rawResult})
}

func errorEnvelope(code, message string) ([]byte, error) {
	return json.Marshal(rpcEnvelope{
		OK:    false,
		Error: &rpcError{Code: code, Message: message},
	})
}
