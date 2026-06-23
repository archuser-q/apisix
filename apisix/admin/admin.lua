local core = require("apisix.core")
local resource = require("apisix.admin.resource")
local schema = require("apisix.schema_def")
local plugin  = require("apisix.plugin")
local jwt = require("resty.jwt")
local sha256 = require("resty.sha256")
local str = require("resty.string")
local http = require("resty.http")

local JWT_SECRET = os.getenv("JWT_SECRET")
local CH_HOST = os.getenv("CH_HOST")
local CH_PORT = tonumber(os.getenv("CH_PORT"))
local CH_USER = os.getenv("CH_USER")
local CH_PASSWORD = os.getenv("CH_PASSWORD")
local CH_DATABASE = os.getenv("CH_DATABASE")
local CH_TABLE = os.getenv("CH_TABLE")
local SALT = os.getenv("SALT")
local admin_schema = schema.admin

local function send_login_audit(entry)
    local httpc = http.new()
    httpc:set_timeout(3000)
    local ok, err = httpc:connect(CH_HOST, CH_PORT)
    if not ok then
        core.log.error("login audit: connect failed: ", err)
        return
    end

    local body = core.json.encode(entry)
    local res, err2 = httpc:request({
        method = "POST",
        path = "/",
        body = "INSERT INTO " .. CH_TABLE .. " FORMAT JSONEachRow " .. body,
        headers = {
            ["Content-Type"] = "application/json",
            ["X-ClickHouse-User"] = CH_USER,
            ["X-ClickHouse-Key"] = CH_PASSWORD,
            ["X-ClickHouse-Database"] = CH_DATABASE,
        }
    })

    if not res then
        core.log.error("login audit: send failed: ", err2)
    elseif res.status >= 400 then
        core.log.error("login audit: clickhouse rejected: ", res:read_body())
    end

    httpc:close()
end

local function audit_login(username, success, reason)
    local entry = {
        id = admin_id or "",
        username = username or "",
        success = success,
        reason = reason or "",
        ip = core.request.get_remote_client_ip(ngx.var.r),
        user_agent = ngx.var.http_user_agent or "",
        ts = os.date("!%Y-%m-%d %H:%M:%S", ngx.time()),
    }
    local ok, err = ngx.timer.at(0, function()
        send_login_audit(entry)
    end)
    if not ok then
        core.log.error("login audit: failed to create timer: ", err)
    end
end

local function hash_password(password, username)
    local salt = username .. SALT
    local h = sha256:new()
    h:update(salt .. password)
    return str.to_hex(h:final())
end

local function check_conf(id, conf, need_id)
    if type(conf.status) == "table" and conf.status.status ~= nil then
        conf.status = conf.status.status
    end

    local body_str = core.request.get_body()
    local body, err = core.json.decode(body_str)
    if not body then
        return nil, {error_msg = "invalid request body: " .. (err or "unknown")}
    end

    if id and body.old_password then
        local old_res, _ = core.etcd.get("/admins/" .. id)
        if old_res and old_res.status == 200 then
            local old_admin = old_res.body.node.value
            local old_hashed = hash_password(body.old_password, old_admin.username)
            if old_admin.password ~= old_hashed then
                return nil, {error_msg = "wrong old password"}
            end
        end
    end
    conf.old_password = nil

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

    if body.password ~= nil then
        conf.password = hash_password(body.password, conf.username or id)
    end

    if conf.status == nil then
        conf.status = true
    end
    if conf.role == nil then
        conf.role = "admin"
    end

    core.log.warn("=== ADMIN CHECK_CONF PASSED ===")
    core.log.warn("conf: ", core.json.encode(conf))
    
    return conf.username or id
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

    -- list toàn bộ admins, tìm theo username
    local res, err = core.etcd.get("/admins", true)
    if not res or res.status ~= 200 then
        audit_login(body.username, 500, "etcd error")
        core.response.exit(500, {error_msg = "internal error"})
        return
    end

    local admin = nil
    for _, item in ipairs(res.body.list or {}) do
        if item.value and item.value.username == body.username then
            admin = item.value
            break
        end
    end

    if not admin then
        audit_login(body.username, 404, "admin not found")
        core.response.exit(404, {error_msg = "admin not found"})
        return
    end

    if not admin.status then
        audit_login(body.username, 403, "account disabled")
        core.response.exit(403, {error_msg = "account disabled"})
        return
    end

    local hashed = hash_password(body.password, admin.username)
    if admin.password ~= hashed then
        audit_login(body.username, 401, "invalid password")
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
    audit_login(admin.username, 200, "ok")
    core.response.exit(200, {
        id = admin.id,
        username = admin.username,
        role = admin.role,
    })
end

local _M = resource.new({
    name = "admins",
    kind = "admin",
    schema = admin_schema,
    checker = check_conf,
    unsupported_methods = {}
})
_M.login = login
return _M