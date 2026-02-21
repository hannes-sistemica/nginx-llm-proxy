-- llm-proxy.lua — Model-based routing for llama-server instances
--
-- Reads config.json at nginx startup, caches in module table.
-- On each request: checks API key, parses model from JSON body,
-- routes to correct llama-server backend.
-- Config reloads on `nginx -s reload` or via /admin/reload.

local cjson = require("cjson.safe")

local _M = {}

local config = nil
local config_path = nil

function _M.init(path)
    config_path = path
    _M.reload()
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
    ngx.log(ngx.NOTICE, "llm-proxy: loaded ", _M.count_models(), " models")
    if not config.api_key or config.api_key == "" then
        ngx.log(ngx.WARN, "llm-proxy: no api_key in config — auth is disabled, all requests will be accepted")
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

function _M.check_auth()
    if not config or not config.api_key then
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
    if token ~= config.api_key then
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

    return true
end

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

    local backend = config.models[model].backend
    ngx.var.backend = "http://" .. backend
end

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

return _M
