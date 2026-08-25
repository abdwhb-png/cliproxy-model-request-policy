# CLIProxyAPI Model Request Policy

Request-interceptor plugin for exact, post-auth CLIProxyAPI header policies. It leaves request bodies, auth metadata, credential selection, and transport execution to CLIProxyAPI.

## Behavior

- Native ABI version 1, RPC schema version 3.
- Declares only `request_interceptor`.
- Before-auth interception always returns an empty no-op response.
- After-auth interception matches exact requested model, optional exact upstream models, allowed source formats, and exact target format.
- Matching rules return configured non-sensitive header updates only.
- Invalid reconfiguration preserves the last valid immutable snapshot.

The plugin never logs or returns request bodies, credentials, auth metadata, or configured secrets. It never terminates requests.

## Configuration

```yaml
plugins:
  configs:
    cliproxy-model-request-policy:
      enabled: true
      priority: 100
      rules:
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
```

Requested and upstream model matching is exact. Omit `upstream-models` to allow any upstream model for the requested alias. Formats are normalized to lowercase and must be known CLIProxyAPI formats.

Configuration rejects empty model or header names, unknown formats, CR/LF in header names or values, and credential-bearing headers such as authorization, cookies, API keys, tokens, and secrets.

## Commands

```bash
make verify
make build
```

`make build` produces `dist/cliproxy-model-request-policy.so` for Linux AMD64. Build artifacts remain local and must not be committed.

## Integration

Mount the built library read-only at `/CLIProxyAPI/plugins/cliproxy-model-request-policy.so`, enable plugins globally, and configure `plugins.configs.cliproxy-model-request-policy`.

Runtime install, reload, restart, and active-config migration require separate deployment approval. A native plugin shares the CLIProxyAPI process and privileges.

## Limits

- Rules only update headers. They do not rewrite bodies, URLs, models, or credentials.
- State is process-local and resets on valid reconfiguration or shutdown.
- Compatibility depends on CLIProxyAPI RPC schema 3 and the `X-OpenAI-Internal-Codex-Responses-Lite` executor contract.
