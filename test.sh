#!/usr/bin/env bash
#
# test.sh — Integration tests for llm-proxy
#
# Spins up dummy backends, configures nginx, runs all tests, cleans up.
#
# Usage:
#   ./test.sh              # test against localhost:4444
#   ./test.sh 10.0.0.5    # test against remote host on port 4000
#   LLM_PROXY_PORT=4000 ./test.sh  # custom port

set -euo pipefail

HOST="${1:-localhost}"
PORT="${LLM_PROXY_PORT:-4444}"
BASE="http://${HOST}:${PORT}"
KEY="test-key-123"
ADMIN_PW="test-admin-pw"
CLEANUP_PIDS=()
PASSED=0
FAILED=0
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Colors ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────

cleanup() {
    for pid in "${CLEANUP_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    if [ "$HOST" = "localhost" ] && [ -f /tmp/llm-proxy-test-nginx.conf ]; then
        sudo rm -f /etc/nginx/sites-enabled/llm-proxy-test 2>/dev/null || true
        sudo nginx -s reload 2>/dev/null || true
        rm -f /tmp/llm-proxy-test-nginx.conf
        rm -rf /tmp/llm-proxy-test
    fi
}
trap cleanup EXIT

assert_contains() {
    local test_name="$1"
    local response="$2"
    local expected="$3"

    if echo "$response" | grep -qF "$expected"; then
        printf "${GREEN}PASS${NC} %s\n" "$test_name"
        PASSED=$((PASSED + 1))
    else
        printf "${RED}FAIL${NC} %s\n" "$test_name"
        printf "  expected: %s\n" "$expected"
        printf "  got:      %s\n" "$response"
        FAILED=$((FAILED + 1))
    fi
}

assert_not_contains() {
    local test_name="$1"
    local response="$2"
    local unexpected="$3"

    if echo "$response" | grep -qF "$unexpected"; then
        printf "${RED}FAIL${NC} %s\n" "$test_name"
        printf "  should not contain: %s\n" "$unexpected"
        printf "  got:                %s\n" "$response"
        FAILED=$((FAILED + 1))
    else
        printf "${GREEN}PASS${NC} %s\n" "$test_name"
        PASSED=$((PASSED + 1))
    fi
}

assert_status() {
    local test_name="$1"
    local status="$2"
    local expected="$3"

    if [ "$status" = "$expected" ]; then
        printf "${GREEN}PASS${NC} %s (HTTP %s)\n" "$test_name" "$status"
        PASSED=$((PASSED + 1))
    else
        printf "${RED}FAIL${NC} %s (expected HTTP %s, got %s)\n" "$test_name" "$expected" "$status"
        FAILED=$((FAILED + 1))
    fi
}

curl_json() {
    curl -s "$@"
}

curl_status() {
    curl -s -o /dev/null -w '%{http_code}' "$@"
}

# ── Local setup (dummy backends + nginx) ──────────────────

setup_local() {
    echo "Setting up local test environment..."

    # Start dummy backends
    python3 "${SCRIPT_DIR}/test-backend.py" 9091 &
    CLEANUP_PIDS+=($!)
    python3 "${SCRIPT_DIR}/test-backend.py" 9092 &
    CLEANUP_PIDS+=($!)
    sleep 1

    # Write test config (in a subdir www-data can write to for CRUD tests)
    mkdir -p /tmp/llm-proxy-test && chmod 777 /tmp/llm-proxy-test
    cat > /tmp/llm-proxy-test/config.json << 'EOF'
{
  "admin_password": "test-admin-pw",
  "api_keys": {
    "test-app": "test-key-123"
  },
  "models": {
    "chat-model": {
      "backend": "127.0.0.1:9091",
      "description": "Test chat model"
    },
    "embed-model": {
      "backend": "127.0.0.1:9092",
      "description": "Test embedding model"
    }
  }
}
EOF
    chmod 666 /tmp/llm-proxy-test/config.json

    # Create static dir symlink for tests
    mkdir -p /tmp/llm-proxy-test-static
    cp "${SCRIPT_DIR}/static/jquery.min.js" /tmp/llm-proxy-test-static/ 2>/dev/null || true

    # Write nginx test config
    cat > /tmp/llm-proxy-test-nginx.conf << NGINX
lua_package_path "${SCRIPT_DIR}/?.lua;;";
lua_shared_dict llm_stats 10m;

init_by_lua_block {
    local proxy = require("llm-proxy")
    proxy.init("/tmp/llm-proxy-test/config.json", "${SCRIPT_DIR}/admin.html")
}

init_worker_by_lua_block {
    require("llm-proxy").init_worker()
}

server {
    listen ${PORT};
    server_name _;
    client_max_body_size 64m;
    lua_need_request_body off;
    client_body_buffer_size 2m;

    location = /health {
        default_type application/json;
        return 200 '{"status":"ok"}';
    }
    location = /v1/models {
        default_type application/json;
        content_by_lua_block {
            local proxy = require("llm-proxy")
            proxy.check_auth()
            proxy.models()
        }
    }
    location /admin/static/ {
        alias ${SCRIPT_DIR}/static/;
    }
    location = /admin {
        allow 127.0.0.1;
        allow ::1;
        deny all;
        content_by_lua_block {
            require("llm-proxy").serve_admin_html()
        }
    }
    location /admin/api/ {
        allow 127.0.0.1;
        allow ::1;
        deny all;
        content_by_lua_block {
            require("llm-proxy").admin_api()
        }
    }
    location = /admin/reload {
        allow 127.0.0.1;
        allow ::1;
        deny all;
        content_by_lua_block {
            local proxy = require("llm-proxy")
            local ok, err = proxy.reload()
            if ok then
                ngx.say('{"status":"reloaded"}')
            else
                ngx.status = 500
                ngx.say('{"status":"error","message":"' .. (err or 'unknown') .. '"}')
            end
        }
    }
    location /v1/ {
        set \$backend "";
        access_by_lua_block {
            local proxy = require("llm-proxy")
            proxy.check_auth()
            proxy.route()
        }
        proxy_pass \$backend;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 600s;

        body_filter_by_lua_block {
            require("llm-proxy").capture_response()
        }
        log_by_lua_block {
            require("llm-proxy").log_usage()
        }
    }
    location / {
        default_type application/json;
        return 404 '{"error":{"message":"Not found","type":"invalid_request_error","code":"404"}}';
    }
}
NGINX

    sudo ln -sf /tmp/llm-proxy-test-nginx.conf /etc/nginx/sites-enabled/llm-proxy-test
    sudo nginx -t 2>&1 || { echo "nginx config test failed"; exit 1; }
    sudo nginx -s reload 2>&1 || sudo systemctl restart nginx
    sleep 1
    echo ""
}

# ── Tests ─────────────────────────────────────────────────

run_tests() {
    echo "Running tests against ${BASE}"
    echo "============================================"
    echo ""

    # ── Proxy tests ────────────────────────────────

    # Health
    local resp
    resp=$(curl_json "${BASE}/health")
    assert_contains "GET /health returns ok" "$resp" '"status":"ok"'

    # Models
    resp=$(curl_json "${BASE}/v1/models" -H "Authorization: Bearer ${KEY}")
    assert_contains "GET /v1/models lists models" "$resp" '"object":"list"'
    assert_contains "GET /v1/models includes chat-model" "$resp" '"id":"chat-model"'
    assert_contains "GET /v1/models includes embed-model" "$resp" '"id":"embed-model"'

    # Chat completion — routes to correct backend
    resp=$(curl_json "${BASE}/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${KEY}" \
        -d '{"model": "chat-model", "messages": [{"role": "user", "content": "Hi"}]}')
    assert_contains "POST /v1/chat/completions routes to chat backend" "$resp" "port 9091"
    assert_contains "POST /v1/chat/completions returns choices" "$resp" '"choices"'

    # Embedding — routes to correct backend
    resp=$(curl_json "${BASE}/v1/embeddings" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${KEY}" \
        -d '{"model": "embed-model", "input": "test"}')
    assert_contains "POST /v1/embeddings routes to embed backend" "$resp" "9092"
    assert_contains "POST /v1/embeddings returns embedding data" "$resp" '"embedding"'

    # Body passthrough — no parameter mangling
    resp=$(curl_json "${BASE}/v1/embeddings" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${KEY}" \
        -d '{"model": "embed-model", "input": "test", "encoding_format": null}')
    assert_contains "POST /v1/embeddings passes body through untouched" "$resp" '"embedding"'

    # Auth: no key
    local status
    status=$(curl_status "${BASE}/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -d '{"model": "chat-model", "messages": [{"role": "user", "content": "Hi"}]}')
    assert_status "No API key returns 401" "$status" "401"

    # Auth: wrong key
    status=$(curl_status "${BASE}/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer wrong-key" \
        -d '{"model": "chat-model", "messages": [{"role": "user", "content": "Hi"}]}')
    assert_status "Wrong API key returns 401" "$status" "401"

    # Unknown model
    resp=$(curl_json "${BASE}/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${KEY}" \
        -d '{"model": "nonexistent", "messages": [{"role": "user", "content": "Hi"}]}')
    assert_contains "Unknown model returns 404 with available list" "$resp" "not found"

    # Empty body
    status=$(curl_status -X POST "${BASE}/v1/chat/completions" \
        -H "Authorization: Bearer ${KEY}")
    assert_status "Empty body returns 400" "$status" "400"

    # Invalid JSON
    status=$(curl_status "${BASE}/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${KEY}" \
        -d 'not json')
    assert_status "Invalid JSON returns 400" "$status" "400"

    # Missing model field
    status=$(curl_status "${BASE}/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${KEY}" \
        -d '{"messages": [{"role": "user", "content": "Hi"}]}')
    assert_status "Missing model field returns 400" "$status" "400"

    # Catch-all
    status=$(curl_status "${BASE}/random-path")
    assert_status "Unknown path returns 404" "$status" "404"

    # Config reload (legacy endpoint)
    if [ "$HOST" = "localhost" ]; then
        resp=$(curl_json "${BASE}/admin/reload")
        assert_contains "POST /admin/reload reloads config" "$resp" '"reloaded"'
    fi

    # ── Admin UI tests ─────────────────────────────

    if [ "$HOST" = "localhost" ]; then
        echo ""
        echo "Admin UI tests"
        echo "--------------------------------------------"

        # Admin page serves HTML
        resp=$(curl_json "${BASE}/admin")
        assert_contains "GET /admin returns HTML" "$resp" "<!DOCTYPE html>"

        # Admin API requires auth
        status=$(curl_status "${BASE}/admin/api/models")
        assert_status "Admin API without password returns 401" "$status" "401"

        # Admin API with wrong password
        status=$(curl_status "${BASE}/admin/api/models" -H "X-Admin-Password: wrong")
        assert_status "Admin API with wrong password returns 401" "$status" "401"

        # Admin API list models
        resp=$(curl_json "${BASE}/admin/api/models" -H "X-Admin-Password: ${ADMIN_PW}")
        assert_contains "GET /admin/api/models lists models" "$resp" '"chat-model"'
        assert_contains "GET /admin/api/models has count" "$resp" '"count"'

        # Admin API health check
        resp=$(curl_json "${BASE}/admin/api/health" -H "X-Admin-Password: ${ADMIN_PW}")
        assert_contains "GET /admin/api/health returns backends" "$resp" '"backends"'
        assert_contains "GET /admin/api/health shows healthy" "$resp" '"healthy"'

        # Admin API add model
        resp=$(curl_json -X POST "${BASE}/admin/api/models" \
            -H "X-Admin-Password: ${ADMIN_PW}" \
            -H "Content-Type: application/json" \
            -d '{"name":"test-new","backend":"127.0.0.1:9091","description":"Test new"}')
        assert_contains "POST /admin/api/models adds model" "$resp" '"ok"'

        # Force all workers to reload config (multi-worker nginx)
        sudo nginx -s reload 2>/dev/null; sleep 1

        # Verify model was added
        resp=$(curl_json "${BASE}/admin/api/models" -H "X-Admin-Password: ${ADMIN_PW}")
        assert_contains "New model appears in list" "$resp" '"test-new"'

        # Admin API update model
        resp=$(curl_json -X PUT "${BASE}/admin/api/models" \
            -H "X-Admin-Password: ${ADMIN_PW}" \
            -H "Content-Type: application/json" \
            -d '{"name":"test-new","backend":"127.0.0.1:9092","description":"Updated"}')
        assert_contains "PUT /admin/api/models updates model" "$resp" '"ok"'

        # Force reload again for update
        sudo nginx -s reload 2>/dev/null; sleep 1

        # Admin API delete model
        resp=$(curl_json -X DELETE "${BASE}/admin/api/models" \
            -H "X-Admin-Password: ${ADMIN_PW}" \
            -H "Content-Type: application/json" \
            -d '{"name":"test-new"}')
        assert_contains "DELETE /admin/api/models removes model" "$resp" '"ok"'

        # Force reload for delete
        sudo nginx -s reload 2>/dev/null; sleep 1

        # Verify model was removed
        resp=$(curl_json "${BASE}/admin/api/models" -H "X-Admin-Password: ${ADMIN_PW}")
        assert_not_contains "Deleted model gone from list" "$resp" '"test-new"'

        # Validation: invalid backend format
        status=$(curl_status -X POST "${BASE}/admin/api/models" \
            -H "X-Admin-Password: ${ADMIN_PW}" \
            -H "Content-Type: application/json" \
            -d '{"name":"bad","backend":"not-a-backend","description":""}')
        assert_status "Invalid backend format returns 400" "$status" "400"

        # Validation: duplicate model name
        status=$(curl_status -X POST "${BASE}/admin/api/models" \
            -H "X-Admin-Password: ${ADMIN_PW}" \
            -H "Content-Type: application/json" \
            -d '{"name":"chat-model","backend":"127.0.0.1:9091","description":""}')
        assert_status "Duplicate model name returns 409" "$status" "409"

        # Admin API reload
        resp=$(curl_json -X POST "${BASE}/admin/api/reload" -H "X-Admin-Password: ${ADMIN_PW}")
        assert_contains "POST /admin/api/reload works" "$resp" '"reloaded"'

        # ── API Key management tests ───────────────

        echo ""
        echo "API key management tests"
        echo "--------------------------------------------"

        # List keys
        resp=$(curl_json "${BASE}/admin/api/keys" -H "X-Admin-Password: ${ADMIN_PW}")
        assert_contains "GET /admin/api/keys lists keys" "$resp" '"test-app"'
        assert_contains "GET /admin/api/keys has count" "$resp" '"count"'

        # Add key with explicit value
        resp=$(curl_json -X POST "${BASE}/admin/api/keys" \
            -H "X-Admin-Password: ${ADMIN_PW}" \
            -H "Content-Type: application/json" \
            -d '{"name":"new-app","key":"sk-new-app-test"}')
        assert_contains "POST /admin/api/keys adds key" "$resp" '"ok"'
        assert_contains "POST /admin/api/keys returns key" "$resp" '"sk-new-app-test"'

        # Force reload
        sudo nginx -s reload 2>/dev/null; sleep 1

        # Verify new key works for proxy auth
        resp=$(curl_json "${BASE}/v1/models" -H "Authorization: Bearer sk-new-app-test")
        assert_contains "New key works for proxy auth" "$resp" '"object":"list"'

        # Add key with auto-generation
        resp=$(curl_json -X POST "${BASE}/admin/api/keys" \
            -H "X-Admin-Password: ${ADMIN_PW}" \
            -H "Content-Type: application/json" \
            -d '{"name":"auto-app"}')
        assert_contains "POST /admin/api/keys auto-generates key" "$resp" '"sk-auto-app-'

        # Duplicate key name
        status=$(curl_status -X POST "${BASE}/admin/api/keys" \
            -H "X-Admin-Password: ${ADMIN_PW}" \
            -H "Content-Type: application/json" \
            -d '{"name":"test-app","key":"sk-dup"}')
        assert_status "Duplicate key name returns 409" "$status" "409"

        # Delete key
        resp=$(curl_json -X DELETE "${BASE}/admin/api/keys" \
            -H "X-Admin-Password: ${ADMIN_PW}" \
            -H "Content-Type: application/json" \
            -d '{"name":"new-app"}')
        assert_contains "DELETE /admin/api/keys removes key" "$resp" '"ok"'

        # Clean up auto-generated key
        curl_json -X DELETE "${BASE}/admin/api/keys" \
            -H "X-Admin-Password: ${ADMIN_PW}" \
            -H "Content-Type: application/json" \
            -d '{"name":"auto-app"}' > /dev/null

        # Force reload after key deletion
        sudo nginx -s reload 2>/dev/null; sleep 1

        # Verify deleted key no longer works
        status=$(curl_status "${BASE}/v1/models" -H "Authorization: Bearer sk-new-app-test")
        assert_status "Deleted key no longer works" "$status" "401"

        # ── Usage stats tests ──────────────────────

        echo ""
        echo "Usage stats tests"
        echo "--------------------------------------------"

        # Reset stats first
        curl_json -X DELETE "${BASE}/admin/api/stats" -H "X-Admin-Password: ${ADMIN_PW}" > /dev/null

        # Make a chat request to generate stats
        curl_json "${BASE}/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${KEY}" \
            -d '{"model": "chat-model", "messages": [{"role": "user", "content": "Hi"}]}' > /dev/null

        # Make an embedding request
        curl_json "${BASE}/v1/embeddings" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${KEY}" \
            -d '{"model": "embed-model", "input": "test"}' > /dev/null

        # Small delay for log phase to complete
        sleep 0.5

        # Check stats
        resp=$(curl_json "${BASE}/admin/api/stats" -H "X-Admin-Password: ${ADMIN_PW}")
        assert_contains "GET /admin/api/stats returns stats" "$resp" '"stats"'
        assert_contains "Stats include test-app key" "$resp" '"test-app"'
        assert_contains "Stats include chat-model" "$resp" '"chat-model"'
        assert_contains "Stats include embed-model" "$resp" '"embed-model"'
        assert_contains "Stats include request count" "$resp" '"requests"'
        assert_contains "Stats include prompt tokens" "$resp" '"prompt_tokens"'
        assert_contains "Stats include total tokens" "$resp" '"total_tokens"'

        # Reset stats
        resp=$(curl_json -X DELETE "${BASE}/admin/api/stats" -H "X-Admin-Password: ${ADMIN_PW}")
        assert_contains "DELETE /admin/api/stats resets" "$resp" '"ok"'

        # Verify stats are empty
        resp=$(curl_json "${BASE}/admin/api/stats" -H "X-Admin-Password: ${ADMIN_PW}")
        assert_not_contains "Stats empty after reset" "$resp" '"test-app"'
    fi

    echo ""
    echo "============================================"
    printf "Results: ${GREEN}%d passed${NC}" "$PASSED"
    if [ "$FAILED" -gt 0 ]; then
        printf ", ${RED}%d failed${NC}" "$FAILED"
    fi
    echo ""

    [ "$FAILED" -eq 0 ]
}

# ── Main ──────────────────────────────────────────────────

if [ "$HOST" = "localhost" ]; then
    setup_local
fi

run_tests
