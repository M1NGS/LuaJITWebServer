-- per-SNI mTLS 测试配置
-- 用法：TEST_MTLS_DIR=/tmp/httpd-mtls luajit-httpd bench/tests/config-mtls.lua
local dir = os.getenv("TEST_MTLS_DIR") or "/tmp/httpd-mtls"
local http_port = tonumber(os.getenv("TEST_HTTP_PORT") or "18083")
local https_port = tonumber(os.getenv("TEST_HTTPS_PORT") or "18445")

local function p(name) return dir .. "/" .. name end

return {
  server = {
    listen = {
      { host = "127.0.0.1", port = http_port },
      { host = "127.0.0.1", port = https_port, tls = true },
    },
    tls = {
      cert = p("default-server.crt"),
      key = p("default-server.key"),
      -- 全局默认要求客户端证书（CA-A）；SNI 可覆盖
      ca = p("ca-a.crt"),
      client_auth = true,
      min_version = "1.2",
      sni = {
        {
          server_name = "a.example.test",
          cert = p("a-server.crt"), key = p("a-server.key"),
          ca = p("ca-a.crt"), client_auth = true,
        },
        {
          server_name = "b.example.test",
          cert = p("b-server.crt"), key = p("b-server.key"),
          ca = p("ca-b.crt"), client_auth = true,
        },
        {
          server_name = "public.example.test",
          cert = p("public-server.crt"), key = p("public-server.key"),
          client_auth = false,   -- 覆盖全局：不要求客户端证书
        },
        {
          -- 不写 ca：继承全局 tls.ca (CA-A)，client_auth=true
          server_name = "inherit.example.test",
          cert = p("a-server.crt"), key = p("a-server.key"),
          client_auth = true,
        },
      },
    },
    tcp = { nodelay = true, keepalive = false, backlog = 1024 },
    limits = { max_body = 64 * 1024 * 1024, idle_timeout = 30 },
  },
  app = "src/app.lua",
}
