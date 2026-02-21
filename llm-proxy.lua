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

    if not config or not config.models or not config.models[model] then
        ngx.status = 404
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = {
                message = "Model '" .. model .. "' not found. Available: " ..
                    _M.list_models(),
                type = "invalid_request_error",
                code = "404"
            }
        }))
        return ngx.exit(404)
    end

    ngx.ctx.model_name = model
    local backend = config.models[model].backend
    ngx.var.backend = "http://" .. backend
end

-- ── Usage tracking ───────────────────────────────

function _M.capture_response()
    local chunk = ngx.arg[1]
    if chunk and #chunk > 0 and chunk:find('"total_tokens"') then
        ngx.ctx.usage_chunk = chunk
    end
end

function _M.log_usage()
    local key_name = ngx.ctx.api_key_name or "_anonymous"
    local model = ngx.ctx.model_name
    if not model then return end

    local dict = ngx.shared.llm_stats
    if not dict then return end

    -- Always count the request
    dict:incr("req|" .. key_name .. "|" .. model, 1, 0)

    -- Extract token usage from response
    local chunk = ngx.ctx.usage_chunk
    if not chunk then return end

    local usage_json = chunk:match('"usage"%s*:%s*(%b{})')
    if not usage_json then return end

    local usage = cjson.decode(usage_json)
    if not usage then return end

    if usage.prompt_tokens then
        dict:incr("pt|" .. key_name .. "|" .. model, usage.prompt_tokens, 0)
    end
    if usage.completion_tokens then
        dict:incr("ct|" .. key_name .. "|" .. model, usage.completion_tokens, 0)
    end

    -- Extract token speed from timings (llama.cpp specific)
    local timings_json = chunk:match('"timings"%s*:%s*(%b{})')
    if not timings_json then return end

    local timings = cjson.decode(timings_json)
    if not timings then return end

    if timings.prompt_per_second and timings.prompt_per_second > 0 then
        dict:incr("pps_sum|" .. key_name .. "|" .. model, timings.prompt_per_second, 0)
        dict:incr("pps_cnt|" .. key_name .. "|" .. model, 1, 0)
    end
    if timings.predicted_per_second and timings.predicted_per_second > 0 then
        dict:incr("cps_sum|" .. key_name .. "|" .. model, timings.predicted_per_second, 0)
        dict:incr("cps_cnt|" .. key_name .. "|" .. model, 1, 0)
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
            if s.pps_sum and s.pps_sum > 0 then
                dict:set("pps_sum|" .. key_name .. "|" .. model, s.pps_sum)
            end
            if s.pps_cnt and s.pps_cnt > 0 then
                dict:set("pps_cnt|" .. key_name .. "|" .. model, s.pps_cnt)
            end
            if s.cps_sum and s.cps_sum > 0 then
                dict:set("cps_sum|" .. key_name .. "|" .. model, s.cps_sum)
            end
            if s.cps_cnt and s.cps_cnt > 0 then
                dict:set("cps_cnt|" .. key_name .. "|" .. model, s.cps_cnt)
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
                    pps_sum = 0, pps_cnt = 0, cps_sum = 0, cps_cnt = 0
                }
            end
            local val = dict:get(k) or 0
            local s = stats[key_name][model]
            if prefix == "req" then s.requests = val
            elseif prefix == "pt" then s.prompt_tokens = val
            elseif prefix == "ct" then s.completion_tokens = val
            elseif prefix == "pps_sum" then s.pps_sum = val
            elseif prefix == "pps_cnt" then s.pps_cnt = val
            elseif prefix == "cps_sum" then s.cps_sum = val
            elseif prefix == "cps_cnt" then s.cps_cnt = val
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
            models[#models + 1] = {
                id = name,
                object = "model",
                created = 0,
                owned_by = "local",
                description = info.description or ""
            }
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
                models[name] = {
                    backend = info.backend,
                    description = info.description or ""
                }
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

    config.models[data.name] = {
        backend = data.backend,
        description = data.description or ""
    }

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

    local old = { backend = config.models[data.name].backend, description = config.models[data.name].description }
    config.models[data.name] = {
        backend = data.backend,
        description = data.description or ""
    }

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
            s.avg_prompt_speed = s.pps_cnt > 0 and (s.pps_sum / s.pps_cnt) or 0
            s.avg_completion_speed = s.cps_cnt > 0 and (s.cps_sum / s.cps_cnt) or 0
        end
    end

    ngx.say(cjson.encode({ stats = stats }))
end

-- ── Validation ────────────────────────────────────

function _M.validate_model(name, data)
    if not name or name == "" then
        return false, "Model name is required"
    end
    if name:match("[%s/\\|]") then
        return false, "Model name must not contain spaces, slashes, or pipes"
    end
    if not data.backend or data.backend == "" then
        return false, "Backend is required"
    end
    if not data.backend:match("^[%w%.%-]+:%d+$") then
        return false, "Backend must be in host:port format (e.g., 127.0.0.1:8080)"
    end
    return true
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
    if not model or not config or not config.models or not config.models[model] then
        ngx.status = 404
        ngx.say(cjson.encode({ error = "Model not found", available = _M.list_models() }))
        return
    end

    local backend = config.models[model].backend
    local host, port = backend:match("^(.+):(%d+)$")
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

    -- Pass through the backend response
    ngx.say(resp_body)
end

-- ── Health checking ───────────────────────────────

function _M.check_backend_health(host, port)
    local sock = ngx.socket.tcp()
    sock:settimeout(2000)
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

function _M.admin_api_health()
    ngx.header["Content-Type"] = "application/json"

    local backends = {}
    if config and config.models then
        for _, info in pairs(config.models) do
            backends[info.backend] = true
        end
    end

    local results = {}
    local threads = {}
    for backend in pairs(backends) do
        local host, port = backend:match("^(.+):(%d+)$")
        if host and port then
            threads[backend] = ngx.thread.spawn(_M.check_backend_health, host, tonumber(port))
        else
            results[backend] = { status = "down", error = "invalid backend format" }
        end
    end

    for backend, thread in pairs(threads) do
        local ok, res = ngx.thread.wait(thread)
        if ok and res then
            results[backend] = res
        else
            results[backend] = { status = "down", error = "health check failed" }
        end
    end

    ngx.say(cjson.encode({ backends = results }))
end

return _M
