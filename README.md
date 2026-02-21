# llm-proxy

An nginx + Lua reverse proxy that routes OpenAI-compatible API requests to multiple llama-server instances. It reads the `model` field from each request body, looks up the backend from a JSON config file, and proxies the request through.

Under 200 lines of Lua running inside nginx. No SDK rewriting your request body, no parameter injection, no framework to keep updated. The request hits nginx, gets routed, and the response comes back unchanged.

## Why this exists

We were running LiteLLM as a proxy in front of several llama-server instances. It worked for chat completions, but embedding requests kept failing. LiteLLM injects `encoding_format: null` into embedding payloads, and llama.cpp chokes on null string fields. The fix was supposedly in a newer version. It was not.

The deeper problem is that proxies like LiteLLM sit between your client and your inference server and actively modify requests. They strip parameters, inject defaults, and transform payloads to match what they think the backend expects. When the backend is llama-server and the proxy was built for OpenAI, things break in ways that are hard to debug.

llm-proxy does none of that. It authenticates the request, reads the model name, picks the right backend, and gets out of the way. The request body passes through byte-for-byte.

## What it does

- Routes requests by model name to different llama-server ports
- API key authentication (Bearer token)
- Works with any OpenAI-compatible endpoint: `/v1/chat/completions`, `/v1/embeddings`, `/v1/completions`
- SSE streaming
- Lists available models via `/v1/models`
- Config lives in a JSON file, reloads on `nginx -s reload`
- Admin endpoint to reload config without restarting nginx

## Requirements

- nginx with the Lua module (`nginx-extras` on Debian/Ubuntu, or OpenResty)
- `lua-cjson` package
- One or more llama-server instances on localhost

```bash
# Debian / Ubuntu
sudo apt install nginx-extras lua-cjson
```

## Setup

Clone the repo and create your config:

```bash
git clone https://github.com/hannes-sistemica/nginx-llm-proxy.git
cd nginx-llm-proxy
cp config.example.json config.json
```

Edit `config.json` with your models and API key:

```json
{
  "api_key": "your-secret-key",
  "models": {
    "my-model": {
      "backend": "127.0.0.1:8080",
      "description": "My Model 70B (Q4_K_M)"
    },
    "my-embed": {
      "backend": "127.0.0.1:8081",
      "description": "Embedding model"
    }
  }
}
```

If you omit `api_key` or leave it empty, the proxy runs without authentication. A warning is logged at startup so you know it's open.

Edit `nginx.conf` and update the two paths at the top to match your install directory. Then:

```bash
sudo cp nginx.conf /etc/nginx/sites-enabled/llm-proxy
sudo nginx -t
sudo nginx -s reload
```

The proxy is now running on port 4000.

## Usage

```bash
# Chat completion
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret-key" \
  -d '{"model": "my-model", "messages": [{"role": "user", "content": "Hello"}]}'

# Embeddings
curl http://localhost:4000/v1/embeddings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret-key" \
  -d '{"model": "my-embed", "input": "some text to embed"}'

# List models
curl http://localhost:4000/v1/models \
  -H "Authorization: Bearer your-secret-key"

# Health check (no auth)
curl http://localhost:4000/health
```

## Changing configuration

Edit `config.json` and reload:

```bash
# Reload nginx (also reloads Lua modules)
sudo nginx -s reload

# Or reload config only, without restarting nginx (localhost only)
curl http://localhost:4000/admin/reload
```

The `/admin/reload` endpoint is restricted to localhost by nginx `allow/deny` rules.

## Running tests

The test suite starts dummy backends, configures a temporary nginx site, runs 17 integration tests, and cleans up after itself. Needs `sudo` for nginx config management:

```bash
sudo make test
```

Tests cover routing, authentication, error handling, body passthrough, and config reload.

## Files

```
llm-proxy.lua          Routing logic (auth, JSON parse, backend lookup)
nginx.conf             Nginx server block, edit paths before installing
config.example.json    Sample config, copy to config.json
config.json            Your actual config (gitignored)
test.sh                Integration test suite
test-backend.py        Dummy OpenAI-compatible server for tests
Makefile               Shortcuts for test, install, reload, status
```

## How it works

When a request arrives at nginx on port 4000:

1. Lua reads the request body and parses the JSON
2. It extracts the `model` field and looks it up in the config table
3. It sets the `$backend` nginx variable to the matching `host:port`
4. `proxy_pass $backend` forwards the request unchanged
5. The response streams back to the client untouched

The config file is read once when nginx starts and cached in the Lua module table. Running `nginx -s reload` re-runs `init_by_lua`, which re-reads the file. The `/admin/reload` endpoint calls the same reload function without restarting workers.

## License

MIT. See [LICENSE](LICENSE).
