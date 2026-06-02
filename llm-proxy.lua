-- llm-proxy.lua — Model-based routing for llama-server instances
--
-- Reads config.json at nginx startup, caches in module table.
-- On each request: checks API key, parses model from JSON body,
-- routes to correct llama-server backend.
-- Config reloads on `nginx -s reload` or via /admin/reload.
-- Admin UI at /admin for browser-based model management.
-- Per-key usage stats persisted to stats.json.

local cjson = require("cjson.safe")

local _M = {}

local config = nil
local config_path = nil
local stats_path = nil
local admin_html_path = nil
local admin_html_cache = nil

-- ── Init & Reload ─────────────────────────────────

function _M.init(path, html_path)
    config_path = path
    stats_path = path:gsub("[^/]+$", "stats.json")
    admin_html_path = html_path
    _M.reload()
end

function _M.init_worker()
    if ngx.worker.id() ~= 0 then return end
    _M.load_stats()
    ngx.timer.every(30, function(premature)
        if premature then return end
        _M.save_stats()
    end)
    -- Start periodic health checks
    local interval = (config and config.health_check_interval) or 30
    ngx.timer.every(interval, function(premature)
        if premature then return end
        _M.run_health_checks()
    end)
    -- Run initial health check after 2s
    ngx.timer.at(2, function() _M.run_health_checks() end)
end

function _M.reload()
    local f, err = io.open(config_path, "r")
    if not f then
        ngx.log(ngx.ERR, "llm-proxy: cannot open config: ", err)
        return false, "cannot open config: " .. (err or "unknown")
    end
    local content = f:read("*a")
    f:close()

    local parsed, parse_err = cjson.decode(content)
    if not parsed then
        ngx.log(ngx.ERR, "llm-proxy: invalid JSON config: ", parse_err)
        return false, "invalid JSON: " .. (parse_err or "unknown")
    end

    config = parsed
    admin_html_cache = nil

    local key_count = _M.count_keys()
    ngx.log(ngx.NOTICE, "llm-proxy: loaded ", _M.count_models(), " models, ", key_count, " API keys")
    if not config.admin_password or config.admin_password == "" then
        ngx.log(ngx.WARN, "llm-proxy: no admin_password in config — admin API is unprotected")
    end
    if key_count == 0 then
        ngx.log(ngx.WARN, "llm-proxy: no api_keys in config — proxy auth is disabled, all requests will be accepted")
    end
    return true
end

function _M.count_models()
    local n = 0
    if config and config.models then
        for _ in pairs(config.models) do n = n + 1 end
    end
    return n
end

function _M.count_keys()
    local n = 0
    if config and config.api_keys then
        for _ in pairs(config.api_keys) do n = n + 1 end
    end
    return n
end

-- ── Auth ──────────────────────────────────────────

function _M.check_auth()
    -- No api_keys configured: allow all requests
    if not config or not config.api_keys or next(config.api_keys) == nil then
        return true
    end

    local auth = ngx.var.http_authorization
    if not auth then
        ngx.status = 401
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = {
                message = "Authentication Error, No api key passed in.",
                type = "auth_error",
                code = "401"
            }
        }))
        return ngx.exit(401)
    end

    local token = auth:match("^[Bb]earer%s+(.+)$")
    if token then
        for name, key in pairs(config.api_keys) do
            if token == key then
                ngx.ctx.api_key_name = name
                return true
            end
        end
    end

    ngx.status = 401
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({
        error = {
            message = "Invalid API key.",
            type = "auth_error",
            code = "401"
        }
    }))
    return ngx.exit(401)
end

function _M.check_admin_auth()
    if not config or not config.admin_password or config.admin_password == "" then
        return true
    end

    local pw = ngx.req.get_headers()["X-Admin-Password"]
    if pw == config.admin_password then
        return true
    end

    ngx.status = 401
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({ error = "Unauthorized" }))
    return ngx.exit(401)
end

-- ── Backend resolution ────────────────────────────

-- Resolve backend URL for a model config.
-- Supports both legacy "backend" string and new "backends" array.
-- Returns url string or nil + error message.
function _M.resolve_backend(model_cfg, forced_backend_name, sticky_key)
    -- New format: backends array with name + url
    if model_cfg.backends and #model_cfg.backends > 0 then
        local dict = ngx.shared.llm_stats
        local default_cap = config and config.default_max_concurrent or 1e9
        local sticky_ttl = config and config.sticky_ttl or 600

        -- Forced backend (@name): exact, bypasses health/capacity/stickiness.
        if forced_backend_name then
            for _, b in ipairs(model_cfg.backends) do
                if b.name == forced_backend_name then
                    return b.url, nil, b.name
                end
            end
            return nil, "Backend '" .. forced_backend_name .. "' not found for this model"
        end

        -- Session stickiness: prefer the backend this session was pinned to
        -- (KV/prefix-cache affinity), but YIELD if it's down or at capacity.
        -- `home` keeps the pin across transient spills so the session returns
        -- to its warm backend once it frees up.
        local home = nil
        if sticky_key and dict then
            local pref = dict:get(sticky_key)
            if pref then
                for _, b in ipairs(model_cfg.backends) do
                    if b.name == pref then
                        home = pref  -- pin still names a real backend
                        if dict:get("health|" .. b.url) ~= "down" then
                            local infl = dict:get("inflight|" .. b.url) or 0
                            local cap = b.max_concurrent or default_cap
                            if infl < cap then
                                dict:set(sticky_key, pref, sticky_ttl)  -- refresh
                                ngx.ctx.sticky_state = "hit:" .. pref
                                return b.url, nil, b.name
                            end
                        end
                        break
                    end
                end
            end
        end

        -- Capacity-aware selection. Preference order; skip down backends; pick
        -- the first healthy one under its concurrency cap; if every healthy
        -- backend is saturated, fall back to the least-loaded (backends queue
        -- internally rather than hard-fail).
        local chosen_url, chosen_name
        local least = nil
        for _, b in ipairs(model_cfg.backends) do
            if (dict and dict:get("health|" .. b.url)) ~= "down" then
                local infl = (dict and dict:get("inflight|" .. b.url)) or 0
                local cap = b.max_concurrent or default_cap
                if infl < cap then
                    chosen_url, chosen_name = b.url, b.name
                    break
                end
                if not least or infl < least.infl then
                    least = { url = b.url, name = b.name, infl = infl }
                end
            end
        end
        if not chosen_url and least then
            chosen_url, chosen_name = least.url, least.name
        end
        if not chosen_url then
            -- None healthy — try first anyway (health might be stale).
            chosen_url, chosen_name = model_cfg.backends[1].url, model_cfg.backends[1].name
        end

        -- Pin the session: keep an existing valid home (transient spill must
        -- not move the session), otherwise pin a new session to where it landed.
        if sticky_key and dict then
            dict:set(sticky_key, home or chosen_name, sticky_ttl)
            ngx.ctx.sticky_state = (home and ("yield:" .. home .. "->" .. chosen_name))
                or ("new:" .. chosen_name)
        end

        return chosen_url, nil, chosen_name
    end

    -- Legacy format: single "backend" string
    if model_cfg.backend then
        return model_cfg.backend, nil, nil
    end

    return nil, "No backend configured"
end

-- ── Routing ───────────────────────────────────────

function _M.route()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()

    if not body then
        local file = ngx.req.get_body_file()
        if file then
            local f = io.open(file, "r")
            if f then
                body = f:read("*a")
                f:close()
            end
        end
    end

    if not body then
        ngx.status = 400
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = {
                message = "Empty request body.",
                type = "invalid_request_error",
                code = "400"
            }
        }))
        return ngx.exit(400)
    end

    local data, err = cjson.decode(body)
    if not data then
        ngx.status = 400
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = {
                message = "Invalid JSON: " .. (err or "unknown"),
                type = "invalid_request_error",
                code = "400"
            }
        }))
        return ngx.exit(400)
    end

    local model = data.model
    if not model then
        ngx.status = 400
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = {
                message = "Missing 'model' field in request.",
                type = "invalid_request_error",
                code = "400"
            }
        }))
        return ngx.exit(400)
    end

    -- Parse model@backend syntax
    local model_name, forced_backend = model:match("^(.+)@(.+)$")
    if not model_name then
        model_name = model
        forced_backend = nil
    end

    if not config or not config.models or not config.models[model_name] then
        ngx.status = 404
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = {
                message = "Model '" .. model_name .. "' not found. Available: " ..
                    _M.list_models(),
                type = "invalid_request_error",
                code = "404"
            }
        }))
        return ngx.exit(404)
    end

    ngx.ctx.model_name = model_name
    ngx.ctx.is_stream = data.stream and true or false
    local model_cfg = config.models[model_name]

    -- Session stickiness key (per model + session). Forced @backend skips it.
    local sticky_key = nil
    if not forced_backend then
        local session = ngx.req.get_headers()["X-Session-Id"]
        if session and session ~= "" then
            sticky_key = "sticky|" .. model_name .. "|" .. session
        end
    end

    local backend, resolve_err, backend_name = _M.resolve_backend(model_cfg, forced_backend, sticky_key)
    if not backend then
        ngx.status = 502
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = {
                message = resolve_err or "No backend available",
                type = "server_error",
                code = "502"
            }
        }))
        return ngx.exit(502)
    end

    ngx.ctx.backend_name = backend_name
    ngx.var.backend = "http://" .. backend

    -- Capacity tracking: claim an in-flight slot for the chosen backend;
    -- released in log_usage() when the request finishes (even on error).
    do
        local dict = ngx.shared.llm_stats
        if dict then
            dict:incr("inflight|" .. backend, 1, 0)
            ngx.ctx.inflight_url = backend
        end
    end

    -- Rewrite model name in request body (strip @backend, apply backend_model)
    local rewritten = false
    if model_cfg.backend_model then
        data.model = model_cfg.backend_model
        rewritten = true
    elseif forced_backend then
        -- Strip @backend from model name sent to backend
        data.model = model_name
        rewritten = true
    end
    if rewritten then
        ngx.req.set_body_data(cjson.encode(data))
    end

    -- Strip /v1 prefix for backends that don't use it (e.g. mlx-vlm)
    if model_cfg.strip_v1 then
        local uri = ngx.var.uri
        if uri:sub(1, 3) == "/v1" then
            ngx.req.set_uri(uri:sub(4))
        end
    end
end

-- ── Response tagging ──────────────────────────────

-- Add headers identifying which backend actually served the request, for
-- client-side stats/debugging. Runs in header_filter (before the body
-- streams), reading values stashed by route(). Does NOT touch the body —
-- the upstream's own "model" field is left as-is (normalize separately if a
-- user-facing gateway needs the virtual name instead of the served name).
function _M.tag_response()
    local b = ngx.ctx.backend_name
    if b then ngx.header["X-LLM-Backend"] = b end
    local m = ngx.ctx.model_name
    if m then ngx.header["X-LLM-Model"] = m end
    if ngx.ctx.sticky_state then ngx.header["X-LLM-Sticky"] = ngx.ctx.sticky_state end
end

-- ── Usage tracking ───────────────────────────────

function _M.capture_response()
    local chunk = ngx.arg[1]
    if chunk and #chunk > 0 then
        -- Wall-clock of first→last output chunk = decode time for streamed
        -- responses (used as the speed source when the backend reports no
        -- llama.cpp timings, e.g. vLLM). ngx.now() is request-cached, so
        -- refresh it explicitly each chunk.
        ngx.update_time()
        local now = ngx.now()
        if not ngx.ctx.gen_first then ngx.ctx.gen_first = now end
        ngx.ctx.gen_last = now
        if chunk:find('"total_tokens"') then
            ngx.ctx.usage_chunk = chunk
        end
    end
end

function _M.log_usage()
    local dict = ngx.shared.llm_stats
    if not dict then return end

    -- Release the in-flight slot claimed at dispatch (runs for every finished
    -- request, including errors). Guard against drift below zero.
    local iu = ngx.ctx.inflight_url
    if iu then
        local n = dict:incr("inflight|" .. iu, -1)
        if n and n < 0 then dict:set("inflight|" .. iu, 0) end
        ngx.ctx.inflight_url = nil
    end

    local key_name = ngx.ctx.api_key_name or "_anonymous"
    local model = ngx.ctx.model_name
    if not model then return end

    -- Stats are keyed per model AND per backend that actually served the
    -- request (set by route()), so a virtual model split across backends
    -- (e.g. qwen36-27b -> proart/strix) shows separate rows. Legacy
    -- single-"backend" models have no backend name -> keyed by model alone.
    local backend = ngx.ctx.backend_name
    local label = model
    if backend and backend ~= "" then label = model .. "@" .. backend end
    local base = key_name .. "|" .. label

    -- Always count the request
    dict:incr("req|" .. base, 1, 0)

    -- Extract token usage from response
    local chunk = ngx.ctx.usage_chunk
    if not chunk then return end

    local usage_json = chunk:match('"usage"%s*:%s*(%b{})')
    if not usage_json then return end

    local usage = cjson.decode(usage_json)
    if not usage then return end

    if usage.prompt_tokens then
        dict:incr("pt|" .. base, usage.prompt_tokens, 0)
    end
    if usage.completion_tokens then
        dict:incr("ct|" .. base, usage.completion_tokens, 0)
    end

    -- ── Token-weighted speed: accumulate Σtokens and Σtime, report Σtok/Σtime
    -- (NOT a mean of per-request rates — that's dominated by tiny generations
    -- where predicted_ms→0 blows the rate to millions). Time source priority:
    --   1. llama.cpp timings.predicted_ms / prompt_ms  (exact, excludes queue)
    --   2. stream first→last-chunk wall time            (vLLM / streamed)
    --   3. skip — never fall back to request_time (it includes prompt+queue)
    local gen_time, gen_tok, prm_time, prm_tok
    local timings_json = chunk:match('"timings"%s*:%s*(%b{})')
    if timings_json then
        local t = cjson.decode(timings_json)
        if t then
            if t.predicted_ms and t.predicted_ms > 0 then
                gen_time = t.predicted_ms / 1000
                gen_tok = t.predicted_n or usage.completion_tokens
            end
            if t.prompt_ms and t.prompt_ms > 0 then
                prm_time = t.prompt_ms / 1000
                prm_tok = t.prompt_n or usage.prompt_tokens
            end
        end
    end
    if not gen_time and ngx.ctx.is_stream and ngx.ctx.gen_first and ngx.ctx.gen_last then
        local dt = ngx.ctx.gen_last - ngx.ctx.gen_first
        if dt > 0 and usage.completion_tokens and usage.completion_tokens > 1 then
            gen_time = dt
            gen_tok = usage.completion_tokens
        end
    end

    if gen_time and gen_tok and gen_tok > 0 then
        dict:incr("gtok|" .. base, gen_tok, 0)
        dict:incr("gtime|" .. base, gen_time, 0)
    end
    if prm_time and prm_tok and prm_tok > 0 then
        dict:incr("ptok|" .. base, prm_tok, 0)
        dict:incr("ptime|" .. base, prm_time, 0)
    end

    -- Time-to-first-token (streamed only): request start → first output chunk.
    -- This is where prefix-cache hits show up — a warm prefix skips prefill so
    -- TTFT drops sharply. Decode tok/s above can't see this.
    if ngx.ctx.is_stream and ngx.ctx.gen_first then
        local ttft = ngx.ctx.gen_first - ngx.req.start_time()
        if ttft > 0 then
            dict:incr("ttftsum|" .. base, ttft, 0)
            dict:incr("ttftcnt|" .. base, 1, 0)
        end
    end
end

-- ── Stats persistence ────────────────────────────

function _M.load_stats()
    local dict = ngx.shared.llm_stats
    if not dict or not stats_path then return end

    local f = io.open(stats_path, "r")
    if not f then return end
    local content = f:read("*a")
    f:close()

    local data = cjson.decode(content)
    if not data then return end

    for key_name, models in pairs(data) do
        for model, s in pairs(models) do
            if s.requests and s.requests > 0 then
                dict:set("req|" .. key_name .. "|" .. model, s.requests)
            end
            if s.prompt_tokens and s.prompt_tokens > 0 then
                dict:set("pt|" .. key_name .. "|" .. model, s.prompt_tokens)
            end
            if s.completion_tokens and s.completion_tokens > 0 then
                dict:set("ct|" .. key_name .. "|" .. model, s.completion_tokens)
            end
            if s.gtok and s.gtok > 0 then
                dict:set("gtok|" .. key_name .. "|" .. model, s.gtok)
            end
            if s.gtime and s.gtime > 0 then
                dict:set("gtime|" .. key_name .. "|" .. model, s.gtime)
            end
            if s.ptok and s.ptok > 0 then
                dict:set("ptok|" .. key_name .. "|" .. model, s.ptok)
            end
            if s.ptime and s.ptime > 0 then
                dict:set("ptime|" .. key_name .. "|" .. model, s.ptime)
            end
            if s.ttftsum and s.ttftsum > 0 then
                dict:set("ttftsum|" .. key_name .. "|" .. model, s.ttftsum)
            end
            if s.ttftcnt and s.ttftcnt > 0 then
                dict:set("ttftcnt|" .. key_name .. "|" .. model, s.ttftcnt)
            end
        end
    end

    ngx.log(ngx.NOTICE, "llm-proxy: loaded stats from ", stats_path)
end

function _M.save_stats()
    local dict = ngx.shared.llm_stats
    if not dict or not stats_path then return end

    local stats = _M.collect_stats(dict)
    if not next(stats) then return end

    local content = _M.json_pretty(stats) .. "\n"
    local tmp = stats_path .. ".tmp"
    local f, err = io.open(tmp, "w")
    if not f then
        ngx.log(ngx.ERR, "llm-proxy: cannot save stats: ", err)
        return
    end
    f:write(content)
    f:close()
    os.rename(tmp, stats_path)
end

function _M.collect_stats(dict)
    local keys = dict:get_keys(4096)
    local stats = {}

    for _, k in ipairs(keys) do
        local prefix, key_name, model = k:match("^([%a_]+)|(.+)|([^|]+)$")
        if prefix and key_name and model then
            if not stats[key_name] then stats[key_name] = {} end
            if not stats[key_name][model] then
                stats[key_name][model] = {
                    requests = 0, prompt_tokens = 0, completion_tokens = 0,
                    gtok = 0, gtime = 0, ptok = 0, ptime = 0, ttftsum = 0, ttftcnt = 0
                }
            end
            local val = dict:get(k) or 0
            local s = stats[key_name][model]
            if prefix == "req" then s.requests = val
            elseif prefix == "pt" then s.prompt_tokens = val
            elseif prefix == "ct" then s.completion_tokens = val
            elseif prefix == "gtok" then s.gtok = val
            elseif prefix == "gtime" then s.gtime = val
            elseif prefix == "ptok" then s.ptok = val
            elseif prefix == "ptime" then s.ptime = val
            elseif prefix == "ttftsum" then s.ttftsum = val
            elseif prefix == "ttftcnt" then s.ttftcnt = val
            end
        end
    end

    return stats
end

-- ── Models endpoint ───────────────────────────────

function _M.list_models()
    local names = {}
    if config and config.models then
        for name, _ in pairs(config.models) do
            names[#names + 1] = name
        end
    end
    table.sort(names)
    return table.concat(names, ", ")
end

function _M.models()
    local models = {}
    if config and config.models then
        for name, info in pairs(config.models) do
            local entry = {
                id = name,
                object = "model",
                created = 0,
                owned_by = "local",
                description = info.description or ""
            }
            -- Include backend names for @backend routing discovery
            if info.backends and #info.backends > 0 then
                local names = {}
                for _, b in ipairs(info.backends) do
                    names[#names + 1] = b.name
                end
                entry.backends = names
            end
            models[#models + 1] = entry
        end
    end
    table.sort(models, function(a, b) return a.id < b.id end)

    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({
        object = "list",
        data = models
    }))
end

-- ── Admin UI ──────────────────────────────────────

function _M.serve_admin_html()
    if not admin_html_path then
        ngx.status = 404
        ngx.say("Admin UI not configured")
        return
    end
    if not admin_html_cache then
        local f, err = io.open(admin_html_path, "r")
        if not f then
            ngx.status = 500
            ngx.say("Admin UI not found: " .. (err or ""))
            return
        end
        admin_html_cache = f:read("*a")
        f:close()
    end
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.say(admin_html_cache)
end

-- ── Admin API router ──────────────────────────────

function _M.admin_api()
    _M.check_admin_auth()

    local uri = ngx.var.uri
    if uri == "/admin/api/models" then
        _M.admin_api_models()
    elseif uri == "/admin/api/keys" then
        _M.admin_api_keys()
    elseif uri == "/admin/api/stats" then
        _M.admin_api_stats()
    elseif uri == "/admin/api/chat" then
        _M.admin_api_chat()
    elseif uri == "/admin/api/health" then
        _M.admin_api_health()
    elseif uri == "/admin/api/reload" then
        local ok, err = _M.reload()
        ngx.header["Content-Type"] = "application/json"
        if ok then
            ngx.say('{"status":"reloaded"}')
        else
            ngx.status = 500
            ngx.say(cjson.encode({ status = "error", message = err or "unknown" }))
        end
    else
        ngx.status = 404
        ngx.header["Content-Type"] = "application/json"
        ngx.say('{"error":"Not found"}')
    end
end

-- ── Admin API: Models CRUD ────────────────────────

function _M.admin_api_models()
    local method = ngx.req.get_method()
    ngx.header["Content-Type"] = "application/json"

    if method == "GET" then
        local models = {}
        if config and config.models then
            for name, info in pairs(config.models) do
                local entry = { description = info.description or "" }
                if info.backends then
                    entry.backends = info.backends
                else
                    entry.backend = info.backend
                end
                if info.backend_model then
                    entry.backend_model = info.backend_model
                end
                if info.strip_v1 then
                    entry.strip_v1 = info.strip_v1
                end
                models[name] = entry
            end
        end
        ngx.say(cjson.encode({ models = models, count = _M.count_models() }))
        return
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        ngx.status = 400
        ngx.say('{"error":"Empty request body"}')
        return
    end

    local data, err = cjson.decode(body)
    if not data then
        ngx.status = 400
        ngx.say(cjson.encode({ error = "Invalid JSON: " .. (err or "") }))
        return
    end

    if method == "POST" then
        _M.admin_add_model(data)
    elseif method == "PUT" then
        _M.admin_update_model(data)
    elseif method == "DELETE" then
        _M.admin_delete_model(data)
    else
        ngx.status = 405
        ngx.say('{"error":"Method not allowed"}')
    end
end

function _M.admin_add_model(data)
    local ok, err = _M.validate_model(data.name, data)
    if not ok then
        ngx.status = 400
        ngx.say(cjson.encode({ error = err }))
        return
    end

    if not config.models then config.models = {} end
    if config.models[data.name] then
        ngx.status = 409
        ngx.say(cjson.encode({ error = "Model '" .. data.name .. "' already exists" }))
        return
    end

    config.models[data.name] = _M.build_model_entry(data)

    local wok, werr = _M.write_config()
    if not wok then
        config.models[data.name] = nil
        ngx.status = 500
        ngx.say(cjson.encode({ error = "Failed to save: " .. (werr or "") }))
        return
    end

    _M.reload()
    ngx.say(cjson.encode({ status = "ok", message = "Model '" .. data.name .. "' added" }))
end

function _M.admin_update_model(data)
    local ok, err = _M.validate_model(data.name, data)
    if not ok then
        ngx.status = 400
        ngx.say(cjson.encode({ error = err }))
        return
    end

    if not config.models or not config.models[data.name] then
        ngx.status = 404
        ngx.say(cjson.encode({ error = "Model '" .. data.name .. "' not found" }))
        return
    end

    local old = config.models[data.name]
    config.models[data.name] = _M.build_model_entry(data)

    local wok, werr = _M.write_config()
    if not wok then
        config.models[data.name] = old
        ngx.status = 500
        ngx.say(cjson.encode({ error = "Failed to save: " .. (werr or "") }))
        return
    end

    _M.reload()
    ngx.say(cjson.encode({ status = "ok", message = "Model '" .. data.name .. "' updated" }))
end

function _M.admin_delete_model(data)
    if not data.name or data.name == "" then
        ngx.status = 400
        ngx.say('{"error":"Model name is required"}')
        return
    end

    if not config.models or not config.models[data.name] then
        ngx.status = 404
        ngx.say(cjson.encode({ error = "Model '" .. data.name .. "' not found" }))
        return
    end

    if _M.count_models() <= 1 then
        ngx.status = 400
        ngx.say('{"error":"Cannot delete the last model"}')
        return
    end

    local old = config.models[data.name]
    config.models[data.name] = nil

    local wok, werr = _M.write_config()
    if not wok then
        config.models[data.name] = old
        ngx.status = 500
        ngx.say(cjson.encode({ error = "Failed to save: " .. (werr or "") }))
        return
    end

    _M.reload()
    ngx.say(cjson.encode({ status = "ok", message = "Model '" .. data.name .. "' removed" }))
end

-- ── Admin API: Keys CRUD ─────────────────────────

function _M.admin_api_keys()
    local method = ngx.req.get_method()
    ngx.header["Content-Type"] = "application/json"

    if method == "GET" then
        local keys = {}
        if config and config.api_keys then
            for name, key in pairs(config.api_keys) do
                local preview = key
                if #key > 12 then
                    preview = key:sub(1, 8) .. "..." .. key:sub(-4)
                end
                keys[#keys + 1] = { name = name, key = key, preview = preview }
            end
        end
        table.sort(keys, function(a, b) return a.name < b.name end)
        ngx.say(cjson.encode({ keys = keys, count = _M.count_keys() }))
        return
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        ngx.status = 400
        ngx.say('{"error":"Empty request body"}')
        return
    end

    local data, err = cjson.decode(body)
    if not data then
        ngx.status = 400
        ngx.say(cjson.encode({ error = "Invalid JSON: " .. (err or "") }))
        return
    end

    if method == "POST" then
        _M.admin_add_key(data)
    elseif method == "DELETE" then
        _M.admin_delete_key(data)
    else
        ngx.status = 405
        ngx.say('{"error":"Method not allowed"}')
    end
end

function _M.admin_add_key(data)
    if not data.name or data.name == "" then
        ngx.status = 400
        ngx.say('{"error":"Key name is required"}')
        return
    end
    if data.name:match("[%s/\\|]") then
        ngx.status = 400
        ngx.say('{"error":"Key name must not contain spaces, slashes, or pipes"}')
        return
    end

    if not data.key or data.key == "" then
        local bytes = {}
        local f = io.open("/dev/urandom", "rb")
        if f then
            local raw = f:read(16)
            f:close()
            for i = 1, #raw do
                bytes[#bytes + 1] = string.format("%02x", raw:byte(i))
            end
        end
        data.key = "sk-" .. data.name .. "-" .. table.concat(bytes)
    end

    if not config.api_keys then config.api_keys = {} end
    if config.api_keys[data.name] then
        ngx.status = 409
        ngx.say(cjson.encode({ error = "Key '" .. data.name .. "' already exists" }))
        return
    end

    config.api_keys[data.name] = data.key

    local wok, werr = _M.write_config()
    if not wok then
        config.api_keys[data.name] = nil
        ngx.status = 500
        ngx.say(cjson.encode({ error = "Failed to save: " .. (werr or "") }))
        return
    end

    _M.reload()
    ngx.say(cjson.encode({ status = "ok", key = data.key, message = "Key '" .. data.name .. "' added" }))
end

function _M.admin_delete_key(data)
    if not data.name or data.name == "" then
        ngx.status = 400
        ngx.say('{"error":"Key name is required"}')
        return
    end

    if not config.api_keys or not config.api_keys[data.name] then
        ngx.status = 404
        ngx.say(cjson.encode({ error = "Key '" .. data.name .. "' not found" }))
        return
    end

    local old = config.api_keys[data.name]
    config.api_keys[data.name] = nil

    local wok, werr = _M.write_config()
    if not wok then
        config.api_keys[data.name] = old
        ngx.status = 500
        ngx.say(cjson.encode({ error = "Failed to save: " .. (werr or "") }))
        return
    end

    _M.reload()
    ngx.say(cjson.encode({ status = "ok", message = "Key '" .. data.name .. "' removed" }))
end

-- ── Admin API: Stats ─────────────────────────────

function _M.admin_api_stats()
    local method = ngx.req.get_method()
    ngx.header["Content-Type"] = "application/json"

    local dict = ngx.shared.llm_stats
    if not dict then
        ngx.say('{"stats":{}}')
        return
    end

    if method == "DELETE" then
        dict:flush_all()
        if stats_path then
            os.remove(stats_path)
        end
        ngx.say('{"status":"ok","message":"Stats reset"}')
        return
    end

    local stats = _M.collect_stats(dict)

    -- Add computed fields to each entry
    for _, models in pairs(stats) do
        for _, s in pairs(models) do
            s.total_tokens = s.prompt_tokens + s.completion_tokens
            -- Token-weighted: total tokens / total time (0 = no measurable samples yet)
            s.avg_prompt_speed = (s.ptime and s.ptime > 0) and (s.ptok / s.ptime) or 0
            s.avg_completion_speed = (s.gtime and s.gtime > 0) and (s.gtok / s.gtime) or 0
            -- Mean time-to-first-token in ms (streamed requests) — shows prefix-cache benefit
            s.avg_ttft_ms = (s.ttftcnt and s.ttftcnt > 0) and (s.ttftsum / s.ttftcnt * 1000) or 0
        end
    end

    ngx.say(cjson.encode({ stats = stats }))
end

-- ── Model entry builder ──────────────────────────

function _M.build_model_entry(data)
    local entry = { description = data.description or "" }
    if data.backends and type(data.backends) == "table" and #data.backends > 0 then
        entry.backends = data.backends
    elseif data.backend then
        entry.backend = data.backend
    end
    if data.backend_model then entry.backend_model = data.backend_model end
    if data.strip_v1 then entry.strip_v1 = data.strip_v1 end
    return entry
end

-- ── Validation ────────────────────────────────────

function _M.validate_model(name, data)
    if not name or name == "" then
        return false, "Model name is required"
    end
    if name:match("[%s/\\|@]") then
        return false, "Model name must not contain spaces, slashes, pipes, or @"
    end
    -- Accept either "backend" (legacy) or "backends" (new array format)
    if data.backends and type(data.backends) == "table" and #data.backends > 0 then
        for i, b in ipairs(data.backends) do
            if not b.url or b.url == "" then
                return false, "Backend #" .. i .. " missing url"
            end
            if not b.url:match("^[%w%.%-]+:%d+$") then
                return false, "Backend #" .. i .. " url must be in host:port format"
            end
            if not b.name or b.name == "" then
                return false, "Backend #" .. i .. " missing name"
            end
        end
        return true
    elseif data.backend and data.backend ~= "" then
        if not data.backend:match("^[%w%.%-]+:%d+$") then
            return false, "Backend must be in host:port format (e.g., 127.0.0.1:8080)"
        end
        return true
    end
    return false, "Backend is required (provide 'backend' or 'backends' array)"
end

-- ── Config persistence ────────────────────────────

function _M.json_pretty(val, indent)
    indent = indent or ""
    local next_indent = indent .. "  "
    local t = type(val)

    if t == "table" then
        if #val > 0 or next(val) == nil then
            if next(val) == nil then return "{}" end
            local items = {}
            for i = 1, #val do
                items[i] = next_indent .. _M.json_pretty(val[i], next_indent)
            end
            return "[\n" .. table.concat(items, ",\n") .. "\n" .. indent .. "]"
        else
            local keys = {}
            for k in pairs(val) do keys[#keys + 1] = k end
            table.sort(keys)
            local items = {}
            for _, k in ipairs(keys) do
                items[#items + 1] = next_indent .. '"' .. k .. '": ' .. _M.json_pretty(val[k], next_indent)
            end
            return "{\n" .. table.concat(items, ",\n") .. "\n" .. indent .. "}"
        end
    elseif t == "string" then
        return cjson.encode(val)
    elseif t == "number" or t == "boolean" then
        return tostring(val)
    else
        return "null"
    end
end

function _M.write_config()
    local content = _M.json_pretty(config) .. "\n"
    local tmp_path = config_path .. ".tmp"

    local f, err = io.open(tmp_path, "w")
    if not f then
        return false, "Cannot write config: " .. (err or "unknown")
    end
    f:write(content)
    f:close()

    local ok, rename_err = os.rename(tmp_path, config_path)
    if not ok then
        os.remove(tmp_path)
        return false, "Cannot rename config: " .. (rename_err or "unknown")
    end
    return true
end

-- ── Chat playground ──────────────────────────────

function _M.admin_api_chat()
    ngx.header["Content-Type"] = "application/json"

    if ngx.req.get_method() ~= "POST" then
        ngx.status = 405
        ngx.say('{"error":"Method not allowed"}')
        return
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        ngx.status = 400
        ngx.say('{"error":"Empty request body"}')
        return
    end

    local data, err = cjson.decode(body)
    if not data then
        ngx.status = 400
        ngx.say(cjson.encode({ error = "Invalid JSON: " .. (err or "") }))
        return
    end

    local model = data.model
    -- Parse model@backend for playground too
    local model_name, forced_backend = model:match("^(.+)@(.+)$")
    if not model_name then model_name = model end

    if not config or not config.models or not config.models[model_name] then
        ngx.status = 404
        ngx.say(cjson.encode({ error = "Model not found", available = _M.list_models() }))
        return
    end

    local model_cfg = config.models[model_name]
    local backend_url, resolve_err = _M.resolve_backend(model_cfg, forced_backend)
    if not backend_url then
        ngx.status = 502
        ngx.say(cjson.encode({ error = resolve_err or "No backend available" }))
        return
    end

    local host, port = backend_url:match("^(.+):(%d+)$")
    if not host or not port then
        ngx.status = 500
        ngx.say(cjson.encode({ error = "Invalid backend format" }))
        return
    end

    -- Build chat completion payload
    local payload = cjson.encode({
        model = model,
        messages = {{ role = "user", content = data.prompt or "" }},
        max_tokens = data.max_tokens or 256,
        temperature = data.temperature or 0.7
    })

    -- Connect to backend directly
    local sock = ngx.socket.tcp()
    sock:settimeout(60000)
    local ok, conn_err = sock:connect(host, tonumber(port))
    if not ok then
        ngx.status = 502
        ngx.say(cjson.encode({ error = "Backend connection failed: " .. (conn_err or "") }))
        return
    end

    -- Send HTTP request
    local req = "POST /v1/chat/completions HTTP/1.0\r\n"
        .. "Host: " .. host .. "\r\n"
        .. "Content-Type: application/json\r\n"
        .. "Content-Length: " .. #payload .. "\r\n"
        .. "Connection: close\r\n"
        .. "\r\n"
        .. payload

    sock:send(req)

    -- Read status line
    local status_line = sock:receive("*l")
    if not status_line then
        sock:close()
        ngx.status = 502
        ngx.say('{"error":"No response from backend"}')
        return
    end

    -- Read headers
    local content_length = nil
    while true do
        local line = sock:receive("*l")
        if not line or line == "" then break end
        local cl = line:match("^[Cc]ontent%-[Ll]ength:%s*(%d+)")
        if cl then content_length = tonumber(cl) end
    end

    -- Read body
    local resp_body
    if content_length then
        resp_body = sock:receive(content_length)
    else
        resp_body = sock:receive("*a")
    end
    sock:close()

    if not resp_body then
        ngx.status = 502
        ngx.say('{"error":"Empty response from backend"}')
        return
    end

    -- Track usage stats from playground requests
    local dict = ngx.shared.llm_stats
    if dict then
        local key_name = "_playground"
        dict:incr("req|" .. key_name .. "|" .. model, 1, 0)

        local usage_json = resp_body:match('"usage"%s*:%s*(%b{})')
        if usage_json then
            local usage = cjson.decode(usage_json)
            if usage then
                if usage.prompt_tokens then
                    dict:incr("pt|" .. key_name .. "|" .. model, usage.prompt_tokens, 0)
                end
                if usage.completion_tokens then
                    dict:incr("ct|" .. key_name .. "|" .. model, usage.completion_tokens, 0)
                end
            end
        end

        local timings_json = resp_body:match('"timings"%s*:%s*(%b{})')
        if timings_json then
            local timings = cjson.decode(timings_json)
            if timings then
                if timings.prompt_per_second and timings.prompt_per_second > 0 then
                    dict:incr("pps_sum|" .. key_name .. "|" .. model, timings.prompt_per_second, 0)
                    dict:incr("pps_cnt|" .. key_name .. "|" .. model, 1, 0)
                end
                if timings.predicted_per_second and timings.predicted_per_second > 0 then
                    dict:incr("cps_sum|" .. key_name .. "|" .. model, timings.predicted_per_second, 0)
                    dict:incr("cps_cnt|" .. key_name .. "|" .. model, 1, 0)
                end
            end
        end
    end

    -- Pass through the backend response
    ngx.say(resp_body)
end

-- ── Health checking ───────────────────────────────

function _M.check_backend_health(host, port)
    local sock = ngx.socket.tcp()
    sock:settimeout(3000)
    local ok, err = sock:connect(host, port)
    if not ok then
        return { status = "down", error = err }
    end

    local req = "GET /health HTTP/1.0\r\nHost: " .. host .. "\r\nConnection: close\r\n\r\n"
    sock:send(req)
    local line = sock:receive("*l")
    sock:close()

    if line and line:match("200") then
        return { status = "healthy" }
    else
        return { status = "reachable" }
    end
end

-- Collect all unique backend URLs from config (supports both formats)
function _M.collect_all_backends()
    local backends = {}
    if not config or not config.models then return backends end
    for _, info in pairs(config.models) do
        if info.backends then
            for _, b in ipairs(info.backends) do
                backends[b.url] = b.name or b.url
            end
        elseif info.backend then
            backends[info.backend] = info.backend
        end
    end
    return backends
end

-- Periodic health check — updates shared dict with status per backend URL
function _M.run_health_checks()
    local dict = ngx.shared.llm_stats
    if not dict then return end

    local backends = _M.collect_all_backends()
    local threads = {}

    for url, _ in pairs(backends) do
        local host, port = url:match("^(.+):(%d+)$")
        if host and port then
            threads[url] = ngx.thread.spawn(_M.check_backend_health, host, tonumber(port))
        end
    end

    for url, thread in pairs(threads) do
        local ok, res = ngx.thread.wait(thread)
        local health_key = "health|" .. url
        if ok and res and res.status == "healthy" then
            dict:set(health_key, "healthy", 90)  -- TTL 90s (3x interval)
        elseif ok and res and res.status == "reachable" then
            dict:set(health_key, "reachable", 90)
        else
            dict:set(health_key, "down", 90)
        end
    end
end

function _M.admin_api_health()
    ngx.header["Content-Type"] = "application/json"

    local backends = _M.collect_all_backends()
    local dict = ngx.shared.llm_stats

    local results = {}
    local threads = {}
    for url, name in pairs(backends) do
        local host, port = url:match("^(.+):(%d+)$")
        if host and port then
            threads[url] = { name = name, thread = ngx.thread.spawn(_M.check_backend_health, host, tonumber(port)) }
        else
            results[url] = { name = name, status = "down", error = "invalid backend format" }
        end
    end

    for url, t in pairs(threads) do
        local ok, res = ngx.thread.wait(t.thread)
        if ok and res then
            res.name = t.name
            results[url] = res
        else
            results[url] = { name = t.name, status = "down", error = "health check failed" }
        end
    end

    -- Annotate with current in-flight count (capacity signal).
    for url, r in pairs(results) do
        local n = dict and dict:get("inflight|" .. url) or 0
        r.inflight = (n and n > 0) and n or 0
    end

    ngx.say(cjson.encode({ backends = results }))
end

return _M
