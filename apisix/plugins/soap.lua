local core = require("apisix.core")
local http = require("resty.http")

local plugin_name = "soap"

local schema = {
    type = "object",
    properties = {
        wsdl_url = {
            type = "string"
        },
    },
    required = { "wsdl_url" },
}

local plugin_attr_schema = {
    type = "object",
    properties = {
        endpoint = {
            type = "string",
            default = "http://127.0.0.1:5000"
        },
        timeout = {
            type = "integer",
            default = 3000
        },
    },
}

local _M = {
    version  = 0.1,
    priority = 1000,
    name     = plugin_name,
    schema   = schema,
    attr_schema = plugin_attr_schema,
}

function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(plugin_attr_schema, conf)
    end
    return core.schema.check(schema, conf)
end

function _M.access(conf, ctx)
    local attr = core.config.local_conf().plugin_attr
    local soap_attr = (attr and attr[plugin_name]) or {}
    local proxy_endpoint = soap_attr.endpoint or "http://172.20.0.2:5000"
    local timeout_ms     = soap_attr.timeout or 3000

    local body, err = core.request.get_body()
    if err then
        return 500, { message = "Failed to read request body" }
    end

    local uri = ctx.var.uri or "/"
    local operation = uri:match("/([^/]+)$") or "Unknown"

    local httpc = http.new()
    httpc:set_timeout(timeout_ms)

    local res, req_err = httpc:request_uri(proxy_endpoint .. "/" .. operation, {
        method  = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["X-WSDL-URL"]   = conf.wsdl_url,
        },
        body = body,
    })

    if not res then
        return 502, { message = "Cannot connect to soap-proxy", detail = req_err }
    end

    if res.status ~= 200 then
        return res.status, { message = "soap-proxy error", detail = res.body }
    end

    return res.status, res.body
end

return _M