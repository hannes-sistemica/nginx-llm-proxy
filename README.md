# llm-proxy

An nginx + Lua reverse proxy that routes OpenAI-compatible API requests to multiple llama-server instances. It reads the `model` field from each request body, looks up the backend from a JSON config file, and proxies the request through.

Under 300 lines of Lua running inside nginx. No SDK rewriting your request body, no parameter injection, no framework to keep updated. The request hits nginx, gets routed, and the response comes back unchanged.

## Why this exists

We were running LiteLLM as a proxy in front of several llama-server instances. It worked for chat completions, but embedding requests kept failing. LiteLLM injects `encoding_format: null` into embedding payloads, and llama.cpp chokes on null string fields. The fix was supposedly in a newer version. It was not.

The deeper problem is that proxies like LiteLLM sit between your client and your inference server and actively modify requests. They strip parameters, inject defaults, and transform payloads to match what they think the backend expects. When the backend is llama-server and the proxy was built for OpenAI, things break in ways that are hard to debug.

llm-proxy does none of that. It authenticates the request, reads the model name, picks the right backend, and gets out of the way. The request body passes through byte-for-byte.

## What it does

- Routes requests by model name to different llama-server ports
- Multiple named API keys (one per app/client)
- Separate admin password for the management UI
- Works with any OpenAI-compatible endpoint: `/v1/chat/completions`, `/v1/embeddings`, `/v1/completions`
- SSE streaming
- Lists available models via `/v1/models`
- Admin UI for models, API keys, and usage stats
- Per-key usage tracking (requests, tokens in/out) persisted to disk
- Config is a JSON file, reloads on `nginx -s reload`

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

Edit `config.json`:

```json
{
  "admin_password": "your-admin-password",
  "api_keys": {
    "my-app": "sk-my-secret-key"
  },
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

Edit `nginx.conf` and update the paths at the top to match your install directory. Then:

```bash
sudo cp nginx.conf /etc/nginx/sites-enabled/llm-proxy
sudo nginx -t
sudo nginx -s reload
```

The proxy is now running on port 4000.

## Configuration

### Admin password

`admin_password` protects the admin UI and API. Set it to any string. If omitted or empty, the admin API is unprotected (a warning is logged at startup).

```json
{
  "admin_password": "your-admin-password"
}
```

### API keys

`api_keys` is a map of name to key. Each name identifies which app or client uses that key. Apps authenticate with `Authorization: Bearer <key>`. If `api_keys` is omitted or empty, the proxy runs without authentication (a warning is logged).

```json
{
  "api_keys": {
    "claude-code": "sk-claude-abc123",
    "obsidian": "sk-obsidian-def456",
    "curl-testing": "sk-test-789"
  }
}
```

You can add keys through the admin UI, or directly in config.json:

```bash
# Edit config.json, add your key to the api_keys object, then reload:
sudo nginx -s reload

# Or reload without restarting nginx:
curl http://localhost:4000/admin/reload
```

### Models

Each model maps a name to a backend `host:port`. The name is what clients pass in the `model` field of their requests.

```json
{
  "models": {
    "qwen3-coder": {
      "backend": "127.0.0.1:8080",
      "description": "Qwen3 Coder 30B (Q4_K_M)"
    },
    "nomic-embed": {
      "backend": "127.0.0.1:8084",
      "description": "Nomic Embed Text v1.5 (F16)"
    }
  }
}
```

Models can also be managed through the admin UI, or by editing config.json and reloading.

## Usage

```bash
# Chat completion
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-my-secret-key" \
  -d '{"model": "my-model", "messages": [{"role": "user", "content": "Hello"}]}'

# Embeddings
curl http://localhost:4000/v1/embeddings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-my-secret-key" \
  -d '{"model": "my-embed", "input": "some text to embed"}'

# List models
curl http://localhost:4000/v1/models \
  -H "Authorization: Bearer sk-my-secret-key"

# Health check (no auth)
curl http://localhost:4000/health
```

## Admin UI

Open `http://localhost:4000/admin` in a browser. Three tabs: Models (health status, add/edit/delete), API Keys (create/revoke, auto-generates `sk-<name>-<random>`), and Stats (per-key request and token counts).

Restricted to localhost by default. For LAN access, uncomment the `allow` lines in `nginx.conf` and set your subnet. Admin operations require the admin password.

## Reloading

```bash
# Full reload (re-reads config, restores stats from disk)
sudo nginx -s reload

# Config-only reload, no worker restart (localhost only)
curl http://localhost:4000/admin/reload
```

## Running tests

The test suite starts dummy backends, configures a temporary nginx site, runs integration tests, and cleans up after itself. Needs `sudo` for nginx config management:

```bash
sudo make test
```

Tests cover routing, authentication, error handling, body passthrough, model CRUD, API key management, and usage stats.

## Files

```
llm-proxy.lua          Routing, auth, admin API, health checks, usage tracking
nginx.conf             Nginx server block, edit paths before installing
admin.html             Admin UI (self-contained HTML + CSS + JS)
static/jquery.min.js   jQuery (served locally)
config.example.json    Sample config, copy to config.json
config.json            Your actual config (gitignored)
stats.json             Usage stats, auto-generated (gitignored)
test.sh                Integration test suite (50 tests)
test-backend.py        Dummy OpenAI-compatible server for tests
Makefile               Shortcuts for test, install, reload, status
```

## How it works

When a request arrives at nginx on port 4000:

1. Lua checks the Bearer token against the `api_keys` table
2. It reads the request body and extracts the `model` field
3. It looks up the backend in the config table
4. It sets the `$backend` nginx variable to the matching `host:port`
5. `proxy_pass $backend` forwards the request unchanged
6. On the way back, it captures token usage from the response for stats
7. The response streams back to the client untouched

The config file is read once when nginx starts and cached in the Lua module table. Running `nginx -s reload` re-runs `init_by_lua`, which re-reads the file. Usage stats are kept in a shared memory zone across workers and flushed to `stats.json` every 30 seconds.

## License

MIT. See [LICENSE](LICENSE).
