local core = require("apisix.core")
local resource = require("apisix.admin.resource")
local schema = require("apisix.schema_def")
local plugin  = require("apisix.plugin")
local jwt = require("resty.jwt")
local JWT_SECRET = os.getenv("JWT_SECRET")
local admin_schema = schema.admin

-- Encode library base64
local ngx_encode_base64 = ngx.encode_base64
local ngx_decode_base64 = ngx.decode_base64

local function is_base64(str)
    if type(str) ~= "string" or #str == 0 then
        return false
    end

    if #str % 4 ~= 0 then
        return false
    end

    if not str:match("^[A-Za-z0-9+/]*={0,2}$") then
        return false
    end

    local base_part = str:match("^([^=]*)")
    if base_part and base_part:find("=") then
        return false
    end

    local decoded = ngx.decode_base64(str)
    if decoded == nil then
        return false
    end

    return ngx.encode_base64(decoded) == str
end


local function check_conf(id, conf, need_id)
    conf.id = nil
    if type(conf.status) == "table" and conf.status.status ~= nil then
        conf.status = conf.status.status
    end


    local ok, err = core.schema.check(admin_schema, conf)
    if not ok then
        return nil, {error_msg = "invalid configuration: " .. err}
    end

    if not id then
        if not conf.username or conf.username == "" then 
            return nil, {error_msg = "username is required"}
        end

        if not conf.password or conf.password == "" then 
            return nil, {error_msg = "password is required"}
        end
    end

    if conf.dob then
        local y, m, d = conf.dob:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)$")
        if not y then
            return nil, {error_msg = "invalid dob format"}
        end

        local dob_time = os.time({
            year = tonumber(y),
            month = tonumber(m),
            day = tonumber(d),
            hour = 0
        })

        if dob_time > ngx.time() then
            return nil, {error_msg = "dob cannot be in the future"}
        end
    end

    local body_str = core.request.get_body()
    local body, err = core.json.decode(body_str)
    if not body then
        return nil, {error_msg = "invalid request body: " .. (err or "unknown")}
    end

    if body.password ~= nil then
        if not is_base64(body.password) then
            conf.password = ngx_encode_base64(body.password)
        else
            conf.password = body.password
        end
    end

    if conf.status == nil then
        conf.status = true
    end

    if conf.role == nil then
        conf.role = "admin"
    end

    core.log.warn("=== ADMIN CHECK_CONF PASSED ===")
    core.log.warn("conf: ", core.json.encode(conf))
    
    return conf.username
end

local function login()
    local body_str = core.request.get_body()
    local body, err = core.json.decode(body_str)
    if not body then
        core.response.exit(400, {error_msg = "invalid request body"})
        return
    end

    if not body.username or not body.password then
        core.response.exit(400, {error_msg = "username and password required"})
        return
    end

    local key = "/admins/" .. body.username
    local res, err = core.etcd.get(key)

    if not res or res.status ~= 200 then
        core.response.exit(404, {error_msg = "admin not found"})
        return
    end

    local admin = res.body.node.value

    if not admin.status then
        core.response.exit(403, {error_msg = "account disabled"})
        return
    end

    local encoded = ngx_encode_base64(body.password)
    if admin.password ~= encoded then
        core.response.exit(401, {error_msg = "invalid password"})
        return
    end

    local token = jwt:sign(
        JWT_SECRET,
        {
            header = { typ = "JWT", alg = "HS256" },
            payload = {
                username = admin.username,
                role = admin.role,
                exp = ngx.time() + 86400
            }
        }
    )

    ngx.header["Set-Cookie"] = "token=" .. token
        .. "; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400"

    core.response.exit(200, {
        username = admin.username,
        role = admin.role,
    })
end

local _M = resource.new({
    name = "admins",
    kind = "admin",
    schema = admin_schema,
    checker = check_conf,
    unsupported_methods = {"post"}
})

_M.login = login  -- export ra ngoài

return _M