package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

type ruleConfig struct {
	UpstreamModels []string          `yaml:"upstream-models"`
	SourceFormats  []string          `yaml:"source-formats"`
	TargetFormat   string            `yaml:"target-format"`
	SetHeaders     map[string]string `yaml:"set-headers"`
}

type pluginConfig struct {
	Rules map[string]ruleConfig `yaml:"rules"`
}

type policyRule struct {
	upstreamModels map[string]struct{}
	sourceFormats  map[string]struct{}
	targetFormat   string
	headers        http.Header
}

type policySnapshot struct {
	rules map[string]policyRule
}

type requestPolicyPlugin struct {
	mu       sync.RWMutex
	snapshot policySnapshot
}

func newRequestPolicyPlugin() *requestPolicyPlugin {
	return &requestPolicyPlugin{
		snapshot: policySnapshot{rules: map[string]policyRule{}},
	}
}

func (p *requestPolicyPlugin) Reconfigure(raw []byte) error {
	var decoded pluginConfig
	if err := yaml.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}

	snapshot := policySnapshot{rules: make(map[string]policyRule, len(decoded.Rules))}
	for requestedModel, config := range decoded.Rules {
		normalizedModel := strings.TrimSpace(requestedModel)
		if normalizedModel == "" {
			return fmt.Errorf("requested model is required")
		}
		if _, duplicate := snapshot.rules[normalizedModel]; duplicate {
			return fmt.Errorf("duplicate requested model %q", normalizedModel)
		}

		rule, err := normalizeRule(normalizedModel, config)
		if err != nil {
			return err
		}
		snapshot.rules[normalizedModel] = rule
	}

	p.mu.Lock()
	p.snapshot = snapshot
	p.mu.Unlock()
	return nil
}

func (p *requestPolicyPlugin) Shutdown() {
	p.mu.Lock()
	p.snapshot = policySnapshot{rules: map[string]policyRule{}}
	p.mu.Unlock()
}

func (p *requestPolicyPlugin) InterceptBeforeAuth(
	_ pluginapi.RequestInterceptRequest,
) pluginapi.RequestInterceptResponse {
	return pluginapi.RequestInterceptResponse{}
}

func (p *requestPolicyPlugin) InterceptAfterAuth(
	request pluginapi.RequestInterceptRequest,
) pluginapi.RequestInterceptResponse {
	p.mu.RLock()
	rule, matched := p.snapshot.rules[request.RequestedModel]
	if !matched || !rule.matches(request) {
		p.mu.RUnlock()
		return pluginapi.RequestInterceptResponse{}
	}
	headers := cloneHeader(rule.headers)
	p.mu.RUnlock()

	return pluginapi.RequestInterceptResponse{Headers: headers}
}

func normalizeRule(requestedModel string, config ruleConfig) (policyRule, error) {
	rule := policyRule{
		upstreamModels: make(map[string]struct{}, len(config.UpstreamModels)),
		sourceFormats:  make(map[string]struct{}, len(config.SourceFormats)),
		headers:        make(http.Header, len(config.SetHeaders)),
	}

	for _, model := range config.UpstreamModels {
		normalizedModel := strings.TrimSpace(model)
		if normalizedModel == "" {
			return policyRule{}, fmt.Errorf("model %q has an empty upstream model", requestedModel)
		}
		rule.upstreamModels[normalizedModel] = struct{}{}
	}

	if len(config.SourceFormats) == 0 {
		return policyRule{}, fmt.Errorf("model %q requires at least one source format", requestedModel)
	}
	for _, format := range config.SourceFormats {
		normalizedFormat := normalizeFormat(format)
		if !knownFormat(normalizedFormat) {
			return policyRule{}, fmt.Errorf("model %q has unknown source format %q", requestedModel, format)
		}
		rule.sourceFormats[normalizedFormat] = struct{}{}
	}

	rule.targetFormat = normalizeFormat(config.TargetFormat)
	if !knownFormat(rule.targetFormat) {
		return policyRule{}, fmt.Errorf("model %q has unknown target format %q", requestedModel, config.TargetFormat)
	}

	if len(config.SetHeaders) == 0 {
		return policyRule{}, fmt.Errorf("model %q requires at least one header", requestedModel)
	}
	for name, value := range config.SetHeaders {
		normalizedName := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if normalizedName == "" {
			return policyRule{}, fmt.Errorf("model %q has an empty header name", requestedModel)
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return policyRule{}, fmt.Errorf("model %q header %q contains a line break", requestedModel, normalizedName)
		}
		if sensitiveHeader(normalizedName) {
			return policyRule{}, fmt.Errorf("model %q header %q is sensitive", requestedModel, normalizedName)
		}
		rule.headers.Set(normalizedName, value)
	}

	return rule, nil
}

func (r policyRule) matches(request pluginapi.RequestInterceptRequest) bool {
	if request.ToFormat != r.targetFormat {
		return false
	}
	if _, matched := r.sourceFormats[request.SourceFormat]; !matched {
		return false
	}
	if len(r.upstreamModels) == 0 {
		return true
	}
	_, matched := r.upstreamModels[request.Model]
	return matched
}

func normalizeFormat(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}

func knownFormat(format string) bool {
	switch format {
	case "antigravity", "claude", "codex", "gemini", "interactions", "openai", "openai-response":
		return true
	default:
		return false
	}
}

func sensitiveHeader(name string) bool {
	compact := strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToLower(name))
	if compact == "authorization" || compact == "proxyauthorization" || compact == "cookie" || compact == "setcookie" {
		return true
	}
	return strings.Contains(compact, "apikey") || strings.Contains(compact, "token") || strings.Contains(compact, "secret")
}

func cloneHeader(source http.Header) http.Header {
	cloned := make(http.Header, len(source))
	for name, values := range source {
		cloned[name] = append([]string(nil), values...)
	}
	return cloned
}
