-- 配置库：由构建脚本编译成字节码注入 VM（luajit -b -s），运行时没有源码文件。
-- 注入后导出全局对象 httpd_config；C 在 config.lua 执行后自动调用 httpd_config.load(cfg)，
-- 用户只写普通 table（config = { ... } / return { ... }），不需要调用本库的方法。
--
-- 写入只做类型/长度/数组上限检查；跨字段语义校验由 C 的 validate_log_config 负责。
-- cdef 字符串由 C 注入到全局 __httpd_config_cdef。

local ffi = require("ffi")
ffi.cdef(__httpd_config_cdef)

local root = ffi.cast("httpd_config_t*", __httpd_config_root())
if root == nil then
  error("httpd_config: cannot get C config root")
end

-- ABI 自检：cdef 与 C 编译布局必须一致
local abi = __httpd_config_abi()
assert(ffi.sizeof("httpd_config_t") == abi.config_size,
       "httpd_config: sizeof mismatch; re-run tools/gen_cdef.sh")
assert(ffi.offsetof("httpd_config_t", "log") == abi.off_log,
       "httpd_config: offsetof(log) mismatch; re-run tools/gen_cdef.sh")
assert(ffi.offsetof("httpd_config_t", "log") +
       ffi.offsetof("httpd_log_cfg_t", "file") == abi.off_log_file,
       "httpd_config: offsetof(log.file) mismatch")
assert(ffi.offsetof("httpd_config_t", "log") +
       ffi.offsetof("httpd_log_cfg_t", "otlp") == abi.off_log_otlp,
       "httpd_config: offsetof(log.otlp) mismatch")
assert(ffi.offsetof("httpd_config_t", "log") +
       ffi.offsetof("httpd_log_cfg_t", "syslog") == abi.off_log_syslog,
       "httpd_config: offsetof(log.syslog) mismatch")

local M = { log = {} }

local function mark()
  rawset(_G, "__httpd_config_used", true)
end

local LEVELS = { error = 0, warn = 1, info = 2, debug = 3 }

local function level(v, default)
  if v == nil then return default end
  local n
  if type(v) == "number" then
    n = math.floor(v)
  else
    n = LEVELS[string.lower(tostring(v))]
    if n == nil then error("bad log level: " .. tostring(v)) end
  end
  if n < 0 or n > 3 then error("log level out of range: " .. tostring(v)) end
  return n
end

local function bool(v, default)
  if v == nil then return default and 1 or 0 end
  if type(v) == "boolean" then return v and 1 or 0 end
  if type(v) == "number" then return v ~= 0 and 1 or 0 end
  error("expected boolean, got " .. type(v))
end

local function int(v, lo, hi, what)
  if type(v) ~= "number" then error(what .. " must be a number") end
  local n = math.floor(v)
  if n < lo or n > hi then
    error(string.format("%s out of range: %d (allowed %d..%d)", what, n, lo, hi))
  end
  return n
end

local function ms(v, lo, hi, what)
  if type(v) ~= "number" then error(what .. " must be a number (seconds)") end
  local out = math.floor(v * 1000 + 0.5)
  if out < lo then out = lo end
  if out > hi then out = hi end
  return out
end

local function str(dst, v, what)
  if v == nil then return false end
  if type(v) ~= "string" then error(what .. " must be a string") end
  local cap = ffi.sizeof(dst) - 1
  if #v > cap then
    error(string.format("%s too long: %d > %d", what, #v, cap))
  end
  ffi.fill(dst, ffi.sizeof(dst))
  if #v > 0 then ffi.copy(dst, v, #v) end
  return true
end

local function normalize_url(u)
  if type(u) ~= "string" then error("log.otlp.endpoint must be a string") end
  if not (u:match("^http://") or u:match("^https://")) then
    error("log.otlp.endpoint must start with http:// or https://")
  end
  local start = u:find("://", 1, true) + 3
  local slash = u:find("/", start, true)
  if not slash then return u .. "/v1/logs" end
  if slash == #u then return u:sub(1, slash - 1) .. "/v1/logs" end
  return u
end

local function fill_kv(dst, t, what)
  local cap = math.floor(ffi.sizeof(dst) / ffi.sizeof(dst[0]))
  local n = 0
  if t ~= nil then
    if type(t) ~= "table" then error(what .. " must be a table") end
    for k, v in pairs(t) do
      if type(k) ~= "string" then error(what .. " keys must be strings") end
      if type(v) == "number" then v = tostring(v) end
      if type(v) ~= "string" then
        error(what .. " values must be string/number")
      end
      if n >= cap then
        error(string.format("%s supports at most %d entries", what, cap))
      end
      local e = dst[n]
      str(e.name, k, what .. " key")
      str(e.value, v, what .. " value")
      n = n + 1
    end
  end
  return n
end

-- default_enabled：方法调用（config.log.file{}）传 true；table 写法按旧语义
local function apply_file(t, default_enabled)
  if type(t) ~= "table" then error("log.file must be a table") end
  local f = root.log.file
  f.enabled = bool(t.enabled, default_enabled)

  local ap, ep = t.access_path, t.error_path
  if t.access == nil then
    f.access_on = (type(ap) == "string" and #ap > 0) and 1 or 0
  else
    f.access_on = bool(t.access, 1)
  end
  if t.error == nil then
    f.error_on = (type(ep) == "string" and #ep > 0) and 1 or 0
  else
    f.error_on = bool(t.error, 1)
  end

  f.level = level(t.level, -1)
  str(f.access_path, ap, "log.file.access_path")
  str(f.error_path, ep, "log.file.error_path")

  if t.max_buffer ~= nil then
    f.max_bytes = int(t.max_buffer, 4096, 1 << 30, "log.file.max_buffer")
  end
  if t.flush_interval ~= nil then
    f.flush_ms = ms(t.flush_interval, 10, 60000, "log.file.flush_interval")
  end
  if t.rotate_interval ~= nil then
    if t.rotate_interval > 0 then
      f.rotate_ms = ms(t.rotate_interval, 100, 86400000, "log.file.rotate_interval")
    else
      f.rotate_ms = 0
    end
  end
  if t.rotate_size ~= nil then
    f.rotate_size = int(t.rotate_size, 0, 2 ^ 40, "log.file.rotate_size")
  end
  if t.rotate_keep ~= nil then
    f.rotate_keep = int(t.rotate_keep, 0, 100, "log.file.rotate_keep")
  end
end

local function apply_otlp(t, default_enabled)
  if type(t) ~= "table" then error("log.otlp must be a table") end
  local o = root.log.otlp
  o.enabled = bool(t.enabled, default_enabled)
  o.access_on = bool(t.access, 1)
  o.error_on = bool(t.error, 1)
  o.level = level(t.level, -1)

  if t.endpoint ~= nil then
    str(o.endpoint, normalize_url(t.endpoint), "log.otlp.endpoint")
  end
  str(o.ca, t.ca, "log.otlp.ca")
  o.verify = bool(t.verify, 1)
  str(o.service_name, t.service_name, "log.otlp.service_name")

  o.nheaders = fill_kv(o.headers, t.headers, "log.otlp.headers")
  o.nresource = fill_kv(o.resource, t.resource, "log.otlp.resource")

  if t.batch_max_bytes ~= nil then
    o.batch_max_bytes = int(t.batch_max_bytes, 1024, 1 << 30, "log.otlp.batch_max_bytes")
  end
  if t.batch_max_records ~= nil then
    o.batch_max_records = int(t.batch_max_records, 1, 100000, "log.otlp.batch_max_records")
  end
  if t.flush_interval ~= nil then
    o.flush_ms = ms(t.flush_interval, 10, 3600000, "log.otlp.flush_interval")
  end
  if t.queue_max_bytes ~= nil then
    o.queue_max_bytes = int(t.queue_max_bytes, 4096, 2 ^ 40, "log.otlp.queue_max_bytes")
  end
  if t.timeout ~= nil then
    o.timeout_ms = ms(t.timeout, 1000, 60000, "log.otlp.timeout")
  end
  if t.max_retries ~= nil then
    o.max_retries = int(t.max_retries, 0, 10, "log.otlp.max_retries")
  end
end

local TRANSPORTS = { udp = 0, tcp = 1, tls = 2, unix = 3 }
local FORMATS = { rfc5424 = 0, ["5424"] = 0, rfc3164 = 1, ["3164"] = 1 }
local FACILITIES = {
  kern = 0, user = 1, mail = 2, daemon = 3, auth = 4, syslog = 5,
  lpr = 6, news = 7, uucp = 8, cron = 9, authpriv = 10, ftp = 11,
  local0 = 16, local1 = 17, local2 = 18, local3 = 19,
  local4 = 20, local5 = 21, local6 = 22, local7 = 23,
}

local function apply_syslog(t, default_enabled)
  if type(t) ~= "table" then error("log.syslog must be a table") end
  local s = root.log.syslog
  s.enabled = bool(t.enabled, default_enabled)
  s.access_on = bool(t.access, 1)
  s.error_on = bool(t.error, 1)
  s.level = level(t.level, -1)

  if t.transport ~= nil then
    local n = TRANSPORTS[string.lower(tostring(t.transport))]
    if n == nil then error("log.syslog.transport must be udp/tcp/tls/unix") end
    s.transport = n
  end
  str(s.host, t.host, "log.syslog.host")
  if t.port ~= nil then
    s.port = int(t.port, 1, 65535, "log.syslog.port")
  end
  str(s.path, t.path, "log.syslog.path")

  if t.format ~= nil then
    local n = FORMATS[string.lower(tostring(t.format))]
    if n == nil then error("log.syslog.format must be rfc5424/rfc3164") end
    s.format = n
  end
  if t.facility ~= nil then
    local n
    if type(t.facility) == "number" then
      n = math.floor(t.facility)
    else
      n = FACILITIES[string.lower(tostring(t.facility))]
    end
    if n == nil or n < 0 or n > 23 then error("bad log.syslog.facility") end
    s.facility = n
  end
  str(s.tag, t.tag, "log.syslog.tag")

  if t.queue_max_bytes ~= nil then
    s.queue_max_bytes = int(t.queue_max_bytes, 4096, 2 ^ 40, "log.syslog.queue_max_bytes")
  end
  if t.reconnect_interval ~= nil then
    s.reconnect_ms = ms(t.reconnect_interval, 100, 60000, "log.syslog.reconnect_interval")
  end
  str(s.ca, t.ca, "log.syslog.ca")
  s.verify = bool(t.verify, 1)
end

-- 隐式入口：C 在 config.lua 执行后调用，读取 table 里的 log 段。
-- 语义与旧 parse_log 对齐：file 表存在默认启用；otlp/syslog 必须显式 enabled = true。
function M.load(cfg)
  mark()
  if type(cfg) ~= "table" then
    error("config must be a table")
  end
  local l = cfg.log
  if type(l) ~= "table" then return end

  if l.level ~= nil then
    root.log.level = level(l.level, 2)
  end

  if type(l.file) == "table" then
    apply_file(l.file, true)
  elseif type(l.access) == "string" or type(l.error) == "string" then
    -- 兼容更早的平铺写法：log = { access = "...", error = "...", ... }
    apply_file({
      enabled = true,
      access_path = type(l.access) == "string" and l.access or nil,
      error_path = type(l.error) == "string" and l.error or nil,
      flush_interval = l.flush_interval,
      max_buffer = l.max_buffer,
      rotate_interval = l.rotate_interval,
      rotate_size = l.rotate_size,
      rotate_keep = l.rotate_keep,
    }, true)
  end

  if type(l.otlp) == "table" then
    apply_otlp(l.otlp, false)
  end
  if type(l.syslog) == "table" then
    apply_syslog(l.syslog, false)
  end
end

-- 方法 API 保留（可选写法）：config.log.file{} 等，调用即启用
function M.log.file(t)
  mark()
  apply_file(t or {}, true)
end

function M.log.otlp(t)
  mark()
  apply_otlp(t or {}, true)
end

function M.log.syslog(t)
  mark()
  apply_syslog(t or {}, true)
end

function M.log.level(v)
  mark()
  root.log.level = level(v, 2)
end

-- 导出为全局对象
httpd_config = M
return M
