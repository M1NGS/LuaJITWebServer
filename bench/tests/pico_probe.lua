-- picohttpparser 解析器级探针：直接调用 phr_parse_request，
-- 观察对畸形请求与 UTF-8 多字节内容的接受/拒绝行为。
-- 运行：PICO_SO=<libpicohttpparser.so> luajit tests/pico_probe.lua
local ffi = require("ffi")

local SO = assert(os.getenv("PICO_SO"), "PICO_SO is not set")
local phr = ffi.load(SO)
local MAX_HEADERS = 32

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

local method = ffi.new("const char*[1]")
local method_len = ffi.new("size_t[1]")
local path = ffi.new("const char*[1]")
local path_len = ffi.new("size_t[1]")
local minor = ffi.new("int[1]")
local headers = ffi.new("phr_header[?]", MAX_HEADERS)
local num = ffi.new("size_t[1]")

local function probe(name, req)
  num[0] = MAX_HEADERS
  local rc = phr.phr_parse_request(req, #req, method, method_len, path, path_len,
    minor, headers, num, 0)
  local verdict = rc > 0 and "ACCEPT" or (rc == -2 and "PARTIAL" or "REJECT")
  local extra = ""
  if rc > 0 then
    local m = ffi.string(method[0], tonumber(method_len[0]))
    local p = ffi.string(path[0], tonumber(path_len[0]))
    if #p > 48 then p = p:sub(1, 48) .. "..." end
    extra = string.format("method=%q path=%q minor=%d headers=%d", m, p, minor[0], tonumber(num[0]))
  end
  print(string.format("%-32s rc=%5d %-8s %s", name, rc, verdict, extra))
end

local function many_headers(n)
  local t = { "GET / HTTP/1.1\r\nHost: x\r\n" }
  for i = 1, n do t[#t + 1] = "X-H" .. i .. ": v\r\n" end
  t[#t + 1] = "\r\n"
  return table.concat(t)
end

print("=== baseline ===")
probe("normal GET", "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
probe("keepalive, 3 headers", "GET / HTTP/1.1\r\nHost: x\r\nAccept: */*\r\nUser-Agent: bench\r\n\r\n")
probe("HTTP/1.0", "GET / HTTP/1.0\r\n\r\n")
probe("partial (no blank line)", "GET / HTTP/1.1\r\nHost: x\r\n")

print("\n=== UTF-8 / multibyte ===")
probe("utf8 path raw", "GET /中文/路径 HTTP/1.1\r\nHost: x\r\n\r\n")
probe("utf8 path percent-encoded", "GET /%E4%B8%AD%E6%96%87/%E9%81%8C HTTP/1.1\r\nHost: x\r\n\r\n")
probe("utf8 query raw", "GET /search?q=中文 HTTP/1.1\r\nHost: x\r\n\r\n")
probe("utf8 query percent-encoded", "GET /search?q=%E4%B8%AD%E6%96%87 HTTP/1.1\r\nHost: x\r\n\r\n")
probe("utf8 header value", "GET / HTTP/1.1\r\nHost: x\r\nX-Name: 你好\r\n\r\n")
probe("utf8 header name", "GET / HTTP/1.1\r\nHost: x\r\nX-名字: v\r\n\r\n")
probe("utf8 in method", "获取 / HTTP/1.1\r\nHost: x\r\n\r\n")
probe("emoji in path raw", "GET /😀 HTTP/1.1\r\nHost: x\r\n\r\n")
probe("raw byte 0x80 in path", "GET /\128 HTTP/1.1\r\nHost: x\r\n\r\n")

print("\n=== malformed requests ===")
probe("bad method (space)", "G ET / HTTP/1.1\r\nHost: x\r\n\r\n")
probe("bad version 9.9", "GET / HTTP/9.9\r\nHost: x\r\n\r\n")
probe("no Host (HTTP/1.1)", "GET / HTTP/1.1\r\n\r\n")
probe("bare LF line endings", "GET / HTTP/1.1\nHost: x\n\n")
probe("leading CRLF", "\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
probe("empty request", "")
probe("only CRLF", "\r\n\r\n")
probe("NUL in path", "GET /\0x HTTP/1.1\r\nHost: x\r\n\r\n")
probe("space in path", "GET /a b HTTP/1.1\r\nHost: x\r\n\r\n")
probe("tab in path", "GET /a\tb HTTP/1.1\r\nHost: x\r\n\r\n")
probe("header value CRLF injection", "GET / HTTP/1.1\r\nHost: x\r\nX-Inject: a\r\nInjected: b\r\n\r\n")

print("\n=== semantic conflicts (smuggling vectors) ===")
probe("duplicate Content-Length", "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
probe("TE chunked + Content-Length", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n")
probe("obs-fold header", "GET / HTTP/1.1\r\nHost: x\r\nX-A: a\r\n b\r\n\r\n")

print("\n=== limits ===")
probe("long URI 1 KiB", "GET /" .. string.rep("a", 1024) .. " HTTP/1.1\r\nHost: x\r\n\r\n")
probe("long URI 8 KiB", "GET /" .. string.rep("a", 8192) .. " HTTP/1.1\r\nHost: x\r\n\r\n")
probe("long URI 16 KiB", "GET /" .. string.rep("a", 16384) .. " HTTP/1.1\r\nHost: x\r\n\r\n")
probe("long header value 8 KiB", "GET / HTTP/1.1\r\nHost: x\r\nX-Long: " .. string.rep("b", 8192) .. "\r\n\r\n")
probe("40 headers (cap 32)", many_headers(40))
probe("64 headers (cap 32)", many_headers(64))
probe("header value 0x7f", "GET / HTTP/1.1\r\nHost: x\r\nX-V: \127\r\n\r\n")
probe("header value 0x80", "GET / HTTP/1.1\r\nHost: x\r\nX-V: \128\r\n\r\n")
