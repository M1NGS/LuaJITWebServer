-- luajit-httpd 配置示例
-- 启动：prefix/c-httpd/bin/luajit-httpd src/config.example.lua
-- app 与证书路径都相对于启动时的工作目录（建议在项目根目录启动）。

return {
  server = {
    listen = {
      { host = "0.0.0.0", port = 8080 },                 -- 明文 HTTP
      -- { host = "0.0.0.0", port = 8443, tls = true },  -- HTTPS（需要下面的 tls 配置）
    },

    -- TCP 层选项（所有 listener 共用）
    tcp = {
      nodelay = true,              -- TCP_NODELAY；流式响应必须开，否则有小包延迟
      keepalive = false,           -- SO_KEEPALIVE
      keepalive_delay = 60,        -- 首次探活前的空闲秒数（TCP_KEEPIDLE）
      keepalive_interval = 10,     -- 探活间隔秒数（TCP_KEEPINTVL）
      keepalive_count = 5,         -- 失败次数上限（TCP_KEEPCNT）
      user_timeout = 0,            -- TCP_USER_TIMEOUT，毫秒；0 = 不设置
      backlog = 1024,              -- uv_listen backlog
      reuse_port = false,          -- SO_REUSEPORT（多进程/多实例监听同一端口）
      send_buffer = 0,             -- SO_SNDBUF，0 = 系统默认
      recv_buffer = 0,             -- SO_RCVBUF，0 = 系统默认
    },

    tls = {
      cert = "/etc/ssl/server.crt",      -- PEM，可包含证书链
      key  = "/etc/ssl/server.key",      -- PEM 私钥
      -- ca = "/etc/ssl/ca.crt",         -- client_auth = true 时必填
      min_version = "1.2",               -- "1.2" | "1.3"
      client_auth = false,               -- mTLS
      handshake_timeout = 10,            -- 秒；0 = 不超时
      check_interval = 10,               -- 定时检测证书 st_mtime（秒）；0 = 关闭
      -- alpn = { "http/1.1" },          -- 可选；本服务只支持 HTTP/1.1
      -- ciphers / ciphersuites 暂未应用（使用 mbedTLS 默认）

      -- SNI 多证书：精确匹配优先；通配仅支持 *.suffix（匹配一级标签）
      -- 客户端不带 SNI 或没有匹配项时使用上面的默认 cert/key 和全局 mTLS 策略
      -- 每个 SNI 可单独设置 ca / client_auth；省略则继承全局 tls.ca / client_auth
      -- sni = {
      --   { server_name = "a.example.com", cert = "/etc/ssl/a.crt", key = "/etc/ssl/a.key",
      --     ca = "/etc/ssl/ca-a.crt", client_auth = true },
      --   { server_name = "b.example.com", cert = "/etc/ssl/b.crt", key = "/etc/ssl/b.key",
      --     ca = "/etc/ssl/ca-b.crt", client_auth = true },
      --   { server_name = "public.example.com", cert = "/etc/ssl/public.crt",
      --     key = "/etc/ssl/public.key", client_auth = false },  -- 覆盖全局：不要求客户端证书
      --   { server_name = "inherit.example.com", cert = "/etc/ssl/inherit.crt",
      --     key = "/etc/ssl/inherit.key", client_auth = true }, -- 继承全局 tls.ca
      -- },
    },

    buffers = {
      max_head         = 16 * 1024,       -- 请求头上限
      auto_buffer_body = 1 * 1024 * 1024, -- 小 body 自动缓冲阈值
      read_high_water  = 1 * 1024 * 1024, -- 未交付 body 背压水位
      write_high_water = 8 * 1024 * 1024, -- res:write 返回 false 的水位
      write_low_water  = 256 * 1024,      -- res:drain 恢复水位
      write_hard_limit = 32 * 1024 * 1024,
    },

    limits = {
      max_body        = 128 * 1024 * 1024, -- HTTPD_MAX_BODY 可覆盖
      max_connections = 1024,
      idle_timeout    = 30,                -- 秒；0 = 不超时
      shutdown_timeout = 10,               -- 秒；优雅退出等待在飞请求，0 = 一直等
    },
  },

  -- 固定 nginx 风格日志（uv 线程池异步写）
  log = {
    access = "/var/log/luajit-httpd/access.log",  -- nil/"" 关闭
    error  = "/var/log/luajit-httpd/error.log",   -- nil/"" 回退 stderr
    level  = "info",           -- error | warn | info | debug
    flush_interval = 0.1,      -- 秒
    max_buffer = 4 * 1024 * 1024,
    rotate_interval = 0,       -- 秒；0 = 不按时间切
    rotate_size = 0,           -- 字节；0 = 不按大小切
    rotate_keep = 7,           -- 0 = truncate；>0 保留份数
  },

  app = "src/app.lua",   -- 业务模块：return { handle = function(req, res) ... end }

  -- 客户端证书吊销表（自定义数据库 / mock）
  revocation = {
    enabled = false,
    key = "sha256",              -- 证书 DER 的 SHA-256 指纹
    interval = 30,               -- 定时从 provider 拉取（秒）；0 = 只启动加载
    load_on_start = true,
    max_bytes = 64 * 1024 * 1024,
    max_entries = 500000,
    on_error = "keep",           -- keep（保留旧表）| reject_all（从未成功加载时拒绝所有客户端证书）
    provider = {
      type = "pgsql",            -- 目标形态；P1 用 mock_file 代替直连
      dsn = "postgresql://user:pass@host/db",
      sql = "SELECT fingerprint_sha256 FROM revoked_client_certs",
      mock_file = "/tmp/revoked.txt",  -- 每行一个 SHA-256 hex；正式直连后去掉
    },
  },

  -- 业务配置：C 不解释，Lua 里通过全局 config 读取
  uploader = { uri = "http://127.0.0.1:9000/upload" },
}
