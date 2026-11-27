-- 对照组：luv + picohttpparser（C，零拷贝，无回调）
local uv = require("luv")
local ffi = require("ffi")

local HOST = os.getenv("BENCH_HOST") or "127.0.0.1"
local PORT = tonumber(os.getenv("BENCH_PORT") or "8080")
local SO = assert(os.getenv("PICO_SO"), "PICO_SO is not set")
local BODY = "Hello, World!"
local RESP = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
  .. #BODY .. "\r\n\r\n" .. BODY
local MAX_HEADERS = 32
local MAX_HEAD_SIZE = 16384

local phr = ffi.load(SO)

ffi.cdef[[
typedef struct phr_header {
  const char *name;
  size_t name_len;
  const char *value;
  size_t value_len;
} phr_header;

int phr_parse_request(const char *buf, size_t len,
                      const char **method, size_t *method_len,
                      const char **path, size_t *path_len,
                      int *minor_version,
                      struct phr_header *headers, size_t *num_headers,
                      size_t last_len);
]]

local function new_ctx(stream)
  return {
    stream = stream,
    method = ffi.new("const char*[1]"),
    method_len = ffi.new("size_t[1]"),
    path = ffi.new("const char*[1]"),
    path_len = ffi.new("size_t[1]"),
    minor = ffi.new("int[1]"),
    headers = ffi.new("phr_header[?]", MAX_HEADERS),
    num = ffi.new("size_t[1]"),
    pending = "",
  }
end

local function want_keep_alive(ctx)
  if ctx.minor[0] < 1 then return false end
  local hs = ctx.headers
  local n = tonumber(ctx.num[0])
  for i = 0, n - 1 do
    local nl = tonumber(hs[i].name_len)
    if nl == 10 then
      local first = hs[i].name[0]
      if first == 99 or first == 67 then -- 'c' / 'C'
        if ffi.string(hs[i].name, nl):lower() == "connection" then
          local v = ffi.string(hs[i].value, tonumber(hs[i].value_len)):lower()
          if v == "close" then return false end
        end
      end
    end
  end
  return true
end

local function handle(ctx, chunk)
  local buf = ctx.pending ~= "" and (ctx.pending .. chunk) or chunk
  while true do
    ctx.num[0] = MAX_HEADERS
    local rc = phr.phr_parse_request(buf, #buf, ctx.method, ctx.method_len,
      ctx.path, ctx.path_len, ctx.minor, ctx.headers, ctx.num, 0)
    if rc == -2 then
      ctx.pending = buf
      return #buf <= MAX_HEAD_SIZE
    elseif rc == -1 then
      ctx.pending = ""
      return false
    end
    ctx.pending = ""
    local keep = want_keep_alive(ctx)
    ctx.stream:write(RESP)
    if not keep then return false end
    if rc >= #buf then return true end
    buf = buf:sub(rc + 1)
  end
end

local server
local function on_connection(err)
  assert(not err, err)
  local client = uv.new_tcp()
  server:accept(client)
  local ctx = new_ctx(client)
  client:read_start(function (rerr, data)
    if rerr or not data then
      pcall(client.close, client)
      return
    end
    if not handle(ctx, data) then
      pcall(client.close, client)
    end
  end)
end

server = uv.new_tcp()
server:bind(HOST, PORT)
server:listen(1024, on_connection)
io.stdout:write("picohttpparser+libuv listening on " .. HOST .. ":" .. PORT .. "\n")
uv.run()
