local core = require("apisix.core")
local cjson = require("cjson")

local plugin_name = "acl"

local schema = {
    type = "object",
    properties = {
        allow_labels = {
            type = "object",
            additionalProperties = {
                type = "array",
                items = { type = "string" }
            }
        },
        external_user_label_field = {
            type = "string"
        }
    },
    required = { "allow_labels" }
}

local _M = {
    version  = 0.1,
    priority = 400,
    name     = plugin_name,
    schema   = schema,
}

local function parse_label_values(raw)
    if not raw then return {} end

    if raw:sub(1, 1) == "[" then
        local ok, arr = pcall(cjson.decode, raw)
        if ok and type(arr) == "table" then
            return arr
        end
    end

    return { raw }
end

local function is_allowed(consumer_labels, allow_labels)
    for label_key, allowed_values in pairs(allow_labels) do
        local raw = consumer_labels and consumer_labels[label_key]
        if not raw then
            return false, "missing labels: " .. label_key
        end

        local consumer_values = type(raw) == "table" and raw or parse_label_values(raw)

        local value_set = {}
        for _, v in ipairs(consumer_values) do
            value_set[v] = true
        end

        local matched = false
        for _, av in ipairs(allowed_values) do
            if value_set[av] then
                matched = true
                break
            end
        end

        if not matched then
            return false, "label '" .. label_key .. "' values unmatched"
        end
    end

    return true, nil
end

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

function _M.access(conf, ctx)
    local consumer_labels = {}

    if conf.external_user_label_field then
        local userinfo_header = core.request.header(ctx, "X-Userinfo")
        if not userinfo_header then
            core.response.exit(403, { message = "Userinfo not found" })
            return
        end

        local decoded = ngx.decode_base64(userinfo_header)
        if not decoded then
            core.response.exit(403, { message = "Failed to decode userinfo" })
            return
        end

        local ok, userinfo = pcall(cjson.decode, decoded)
        if not ok then
            core.response.exit(403, { message = "Failed to parse userinfo" })
            return
        end

        local field_value = userinfo[conf.external_user_label_field]
        if field_value then
            consumer_labels[conf.external_user_label_field] = type(field_value) == "table"
                and field_value
                or { field_value }
        end
    else
        local consumer = ctx.consumer
        if not consumer then
            core.response.exit(401, { message = "Authentication required" })
            return
        end
        consumer_labels = consumer.labels or {}
    end

    local allowed, err = is_allowed(consumer_labels, conf.allow_labels)
    if not allowed then
        core.log.warn("ACL denied: ", err)
        core.response.exit(403, { message = "Access denied: " .. (err or "insufficient permissions") })
        return
    end

    core.log.info("ACL granted access")
end

return _M