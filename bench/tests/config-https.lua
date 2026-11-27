-- HTTPS/配置功能测试用（bench/tests/config-https.lua）
-- 从项目根目录启动：luajit-httpd bench/tests/config-https.lua
-- 证书默认用 /tmp/httpd-certs/（测试时由 openssl CLI 生成，可用 TEST_CERT/TEST_KEY 覆盖）

local cert = os.getenv("TEST_CERT") or "/tmp/httpd-certs/cert.pem"
local key  = os.getenv("TEST_KEY")  or "/tmp/httpd-certs/key.pem"
local http_port  = tonumber(os.getenv("TEST_HTTP_PORT") or "18080")
local https_port = tonumber(os.getenv("TEST_HTTPS_PORT") or "18443")

local sni_dir = os.getenv("TEST_SNI_DIR")
local sni = nil
if sni_dir then
  sni = {
    { server_name = "a.example.test", cert = sni_dir .. "/a.crt", key = sni_dir .. "/a.key" },
    { server_name = "*.wild.test", cert = sni_dir .. "/wild.crt", key = sni_dir .. "/wild.key" },
  }
end

return {
  server = {
    listen = {
      { host = "127.0.0.1", port = http_port },
      { host = "127.0.0.1", port = https_port, tls = true },
    },
    tls = {
      cert = cert,
      key = key,
      min_version = "1.2",
      handshake_timeout = 10,
      check_interval = 1,          -- 定时 st_mtime 检测（秒）
      alpn = { "http/1.1" },
      sni = sni,
    },
    tcp = {
      nodelay = true,
      keepalive = os.getenv("TEST_KEEPALIVE") == "1",
      keepalive_delay = tonumber(os.getenv("TEST_KEEPALIVE_DELAY") or "60"),
      keepalive_interval = 10,
      keepalive_count = 5,
      user_timeout = tonumber(os.getenv("TEST_USER_TIMEOUT") or "0"),
      backlog = 1024,
      reuse_port = os.getenv("TEST_REUSE_PORT") == "1",
      send_buffer = tonumber(os.getenv("TEST_SEND_BUFFER") or "0"),
      recv_buffer = tonumber(os.getenv("TEST_RECV_BUFFER") or "0"),
    },
    buffers = {
      max_head = 16 * 1024,
      auto_buffer_body = 1 * 1024 * 1024,
      write_high_water = 8 * 1024 * 1024,
      write_low_water = 256 * 1024,
    },
    limits = {
      max_body = 64 * 1024 * 1024,
      max_connections = 512,
      idle_timeout = 30,
    },
  },
  app = "src/app.lua",
  uploader = { uri = "http://127.0.0.1:9000/upload" },
}
