/*
 * luajit-httpd —— C 宿主 + libuv 多路复用 + picohttpparser + 嵌入式 LuaJIT + mbedTLS
 *
 * 用法：luajit-httpd <config.lua|app.lua> [port]
 *
 * config.lua（新写法）：
 *   return {
 *     server = {
 *       listen = { { host = "0.0.0.0", port = 8080 },
 *                  { host = "0.0.0.0", port = 8443, tls = true } },
 *       tls = { cert = "...", key = "...", min_version = "1.2",
 *               ca = "...", client_auth = false, handshake_timeout = 10,
 *               alpn = { "http/1.1" } },
 *       buffers = { max_head, auto_buffer_body, read_high_water,
 *                   write_high_water, write_low_water, write_hard_limit },
 *       limits = { max_body, max_connections, idle_timeout },
 *     },
 *     app = "app.lua",     -- 业务模块（返回 { handle = function(req, res) }）
 *     uploader = { uri = "..." },  -- 业务配置，C 透传（全局 config）
 *   }
 *
 * app.lua（旧写法，兼容）：
 *   return { handle = function(req, res) ... end }
 *
 *   req.method / req.path（已剥离 query）/ req.query / req.headers
 *   req.has_body       是否有请求体
 *   req.body_size      Content-Length 字节数（无 body 为 0）
 *   req.streaming      body 超过自动缓冲阈值（此时 req.body 为 nil，只能 req:read()）
 *   req.body           小 body（<= AUTO_BUFFER_BODY）时为完整字符串；流式时为 nil
 *   req:read()         协程式读取下一块请求体，返回 chunk 或 nil（body 结束）
 *   req:text(max?)     协程式聚合整个 body：小 body 直接返回 req.body，大 body 逐块拼接
 *
 *   res:write_head(status?, headers?, content_length?)
 *                       给 content_length → Content-Length 模式；否则 HTTP/1.1 chunked、HTTP/1.0 close 定界
 *   res:write(chunk)    写响应体，返回 ok, queue_bytes
 *   res:finish()        结束响应
 *   res:drain()         协程式背压：写队列降到低水位后返回
 *   res:queue_size()    当前写队列字节数
 *   res:header_sent()   响应头是否已发送
 *   res:set_timeout(sec) 本请求 idle 超时（0 = 取消；与 Bun.serve 的 server.timeout 对齐）
 *
 *   handle 返回 table（{status, headers, body}）时按一次性响应处理（兼容旧写法）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <uv.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>

#include "picohttpparser.h"

#define MAX_HEADERS        64
#define MAX_HEAD_SIZE      (16 * 1024)
#define AUTO_BUFFER_BODY   (1024 * 1024)             /* 小 body 自动缓冲阈值（默认） */
/* 流式 body 上限，默认对齐 Bun.serve 的 maxRequestBodySize（128 MiB）；HTTPD_MAX_BODY 可覆盖 */
#define MAX_BODY_STREAM_DEFAULT (128ULL * 1024 * 1024)
static size_t max_body_stream = MAX_BODY_STREAM_DEFAULT;
#define READ_HIGH_WATER    (1024 * 1024)             /* 未交付 body 缓冲高水位（默认） */
#define WRITE_HIGH_WATER   (8 * 1024 * 1024)
#define WRITE_LOW_WATER    (256 * 1024)
#define WRITE_HARD_LIMIT   (32 * 1024 * 1024)
#define BODY_DELIVER_CHUNK (64 * 1024)
#define IDLE_TIMEOUT_MS    (30 * 1000)
#define MAX_RESP_HEAD      (8192)

/* config.lua 可覆盖的运行时参数 */
static size_t g_max_head_size = MAX_HEAD_SIZE;
static size_t g_auto_buffer_body = AUTO_BUFFER_BODY;
static size_t g_read_high_water = READ_HIGH_WATER;
static size_t g_write_high_water = WRITE_HIGH_WATER;
static size_t g_write_low_water = WRITE_LOW_WATER;
static size_t g_write_hard_limit = WRITE_HARD_LIMIT;
static unsigned g_idle_timeout_ms = IDLE_TIMEOUT_MS;
static unsigned g_handshake_timeout_ms = 10 * 1000;
static size_t g_max_connections = 1024;
static size_t g_active_connections = 0;

typedef struct listener_s {
  uv_tcp_t handle;
  int tls;
  char host[128];
  int port;
} listener_t;

static listener_t *g_listeners;
static size_t g_listener_count;

/* ---------- TCP 选项（config.lua server.tcp） ---------- */
typedef struct tcp_opts_s {
  int nodelay;
  int keepalive;
  unsigned keepalive_delay;
  unsigned keepalive_interval;
  unsigned keepalive_count;
  unsigned user_timeout_ms;
  int backlog;
  int reuse_port;
  int send_buffer;
  int recv_buffer;
} tcp_opts_t;

static tcp_opts_t g_tcp = { 1, 0, 60, 10, 5, 0, 1024, 0, 0, 0 };

/* ---------- TLS（mbedTLS 3.6）：证书代，支持 SNI 与热轮换 ---------- */
typedef struct tls_cert_pair_s {
  char server_name[128];
  mbedtls_x509_crt cert;
  mbedtls_pk_context key;
  mbedtls_x509_crt ca;       /* 该 SNI 自己的客户端 CA（可选） */
  int has_ca;
  int client_auth;           /* 该 SNI 生效的客户端证书要求 */
} tls_cert_pair_t;

typedef struct tls_gen_s {
  mbedtls_ssl_config conf;
  mbedtls_x509_crt default_cert;
  mbedtls_pk_context default_key;
  mbedtls_x509_crt ca;
  int has_ca;
  tls_cert_pair_t *sni;
  size_t sni_count;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context drbg;
  int refs;
} tls_gen_t;

static tls_gen_t *g_tls_gen;      /* 当前代（持 1 个引用） */
static int g_tls_enabled;

/* 配置文件里的证书路径等；定时检测按这些路径读取 */
static char g_tls_cert_path[512];
static char g_tls_key_path[512];
static char g_tls_ca_path[512];
static int g_tls_client_auth;
static int g_tls_min13;
static char g_tls_alpn_buf[8][64];
static const char *g_tls_alpn[9];
static int g_tls_alpn_count;

#define MAX_SNI_CERTS 32
static char g_sni_names[MAX_SNI_CERTS][128];
static char g_sni_cert_paths[MAX_SNI_CERTS][512];
static char g_sni_key_paths[MAX_SNI_CERTS][512];
static char g_sni_ca_paths[MAX_SNI_CERTS][512];
static int g_sni_client_auth[MAX_SNI_CERTS];   /* -1 = 继承全局，0/1 = 覆盖 */
static size_t g_sni_count;

/* 定时 st_mtime 检测：路径列表 + 上次快照 */
#define MAX_TLS_PATHS (3 + MAX_SNI_CERTS * 3)
typedef struct {
  time_t sec;
  long nsec;
  int valid;
} tls_stamp_t;
static char g_tls_paths[MAX_TLS_PATHS][512];
static size_t g_tls_path_count;
static tls_stamp_t g_tls_stamps[MAX_TLS_PATHS];
static int g_tls_checking;
static int g_tls_check_interval_ms = 10000;
static uv_timer_t g_tls_check_timer;
static __thread char tls_errbuf[1024];

/* ---------- 客户端证书吊销表（自定义数据库 / mock） ---------- */
typedef struct revoked_store_s {
  uint8_t *keys;      /* cap * 32 */
  uint8_t *used;      /* cap */
  size_t cap;
  size_t count;
} revoked_store_t;

typedef struct revocation_cfg_s {
  int enabled;
  int load_on_start;
  int interval_ms;
  size_t max_bytes;
  size_t max_entries;
  int reject_all;
  char source_file[512];
  char provider_type[32];
  char sql[1024];
  char dsn[512];
  int loaded;
} revocation_cfg_t;

static revocation_cfg_t g_revocation = {
  .enabled = 0,
  .load_on_start = 1,
  .interval_ms = 30000,
  .max_bytes = 64 * 1024 * 1024,
  .max_entries = 500000,
  .reject_all = 0
};
static revoked_store_t *g_revoked;
static int g_revocation_checking;
static uv_timer_t g_revocation_timer;

typedef struct conn_s conn_t;

/* ---------- 日志（固定 nginx 风格格式，uv 线程池异步写） ---------- */
#define LOG_ERROR 0
#define LOG_WARN  1
#define LOG_INFO  2
#define LOG_DEBUG 3

typedef struct log_sink_s {
  int enabled;
  char path[512];
  uv_mutex_t mutex;       /* 保护 pending 队列 */
  uv_mutex_t io_mutex;    /* 串行化写文件与切分 */
  char *pending;
  size_t pending_len;
  size_t pending_cap;
  size_t max_bytes;
  uv_work_t work;
  int in_flight;
  uv_timer_t timer;       /* 定时 flush */
  uv_timer_t rotate_timer;
  int rotate_in_flight;
  int rotate_requested;
  size_t bytes_since_rotate;
  size_t rotate_size;     /* 0 = 不按大小切 */
  int rotate_keep;        /* 0 = truncate；>0 保留份数 */
  int rotate_interval_ms; /* 0 = 不按时间切 */
  unsigned dropped;
} log_sink_t;

static log_sink_t g_access_log;
static log_sink_t g_error_log;
static int g_log_inited;
static int g_log_shutting_down;
static int g_log_level = LOG_INFO;
static int g_log_flush_ms = 100;
static size_t g_log_max_bytes = 4 * 1024 * 1024;
static int g_log_rotate_ms;
static size_t g_log_rotate_size;
static int g_log_rotate_keep = 7;
static char g_log_access_path[512];
static char g_log_error_path[512];

typedef enum {
  ST_HEAD = 0,   /* 等待/解析请求头 */
  ST_BODY,       /* 请求体接收（协程可能 yield "read"） */
  ST_RESPONSE,   /* 响应中（协程可能 yield "drain"） */
  ST_DRAIN,      /* 响应已 finish，等写队列排空 */
} conn_state_t;

typedef enum {
  RESP_NONE = 0,
  RESP_CL,       /* Content-Length */
  RESP_CHUNKED,  /* Transfer-Encoding: chunked */
  RESP_CLOSE,    /* HTTP/1.0，close 定界 */
} resp_mode_t;

typedef struct request_s {
  conn_t *c;
  int co_ref;
  lua_State *co;

  char *head_copy;               /* 头部字节副本，下面的指针都指向它 */
  size_t head_len;
  const char *method; size_t method_len;
  const char *path; size_t path_len;
  const char *query; size_t query_len;
  const char *target; size_t target_len;   /* 原始 request-target（含 query） */
  struct phr_header headers[MAX_HEADERS];
  size_t num_headers;
  int minor;
  int ka;
  int is_head;
  int access_logged;

  size_t body_cl;
  size_t body_received;
  size_t body_delivered;
  char *body_buf;
  size_t body_len;
  size_t body_cap;
  int body_eof;
  int auto_buffer;
  int waiting_read;
  int waiting_drain;
  int discarding;

  resp_mode_t mode;
  int head_sent;
  int body_disabled;
  int status;
  size_t cl;
  size_t written;
  int finished;
  int finish_close_after;
} request_t;

struct conn_s {
  uv_tcp_t handle;
  uv_timer_t timer;
  char *buf;
  size_t len;
  size_t cap;
  conn_state_t state;
  int closing;
  int pending_closes;
  int pending_writes;
  int read_paused;
  int res_ref;           /* 每连接的 res 表（registry ref），闭包 upvalue 指向 &req */
  unsigned idle_timeout_ms;
  int no_timeout;        /* res:set_timeout(0)：本请求不再受 idle 超时约束 */
  char remote_addr[64];  /* 客户端地址，access log 用 */
  conn_t *next;          /* 全局连接链表 */

  int tls;               /* 连接是否 TLS */
  int tls_handshaking;
  tls_gen_t *tls_gen;    /* 握手/连接期间持有的证书代 */
  mbedtls_ssl_context ssl;
  char *tls_in;          /* 未消费的密文 */
  size_t tls_in_len;
  size_t tls_in_cap;
  char *tls_out;         /* 已生成、待 uv_write 的密文 */
  size_t tls_out_len;
  size_t tls_out_cap;

  request_t req;
};

typedef struct {
  uv_write_t req;
  conn_t *conn;
  char data[];
} write_req_t;

static uv_loop_t *loop;
static lua_State *L;
static int app_ref = LUA_NOREF;
static int traceback_ref = LUA_NOREF;
static int stream_lib_ref = LUA_NOREF;

/* 优雅退出：0=running, 1=draining, 2=forced, 3=done */
static conn_t *g_conns;
static size_t g_conn_count;
static int g_shutdown_state;
static uv_timer_t g_shutdown_timer;
static unsigned g_shutdown_timeout_ms = 10000;

static void log_error(int level, const char *fmt, ...);
static void log_access(conn_t *c);
static void shutdown_complete(void);

static void alloc_cb(uv_handle_t *handle, size_t suggested, uv_buf_t *buf);
static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_write(uv_write_t *req, int status);
static void process_buffer(conn_t *c);
static void request_finalize(conn_t *c);
static int tls_flush_out(conn_t *c);
static void tls_pump(conn_t *c);
static void tls_gen_ref(tls_gen_t *g);
static void tls_gen_unref(tls_gen_t *g);

static const char *STREAM_LIB_LUA =
  "local M = {}\n"
  "function M.read(self) return coroutine.yield('read') end\n"
  "function M.drain(self) return coroutine.yield('drain') end\n"
  /* Bun 的 req.text() 对应物：小 body 直接返回 req.body，大 body 协程式聚合 */
  "function M.text(self, max_bytes)\n"
  "  if self.body then return self.body end\n"
  "  if not self.has_body then return '' end\n"
  "  local n, out = 0, {}\n"
  "  while true do\n"
  "    local chunk = self:read()\n"
  "    if not chunk then break end\n"
  "    n = n + #chunk\n"
  "    if max_bytes and n > max_bytes then\n"
  "      error('body exceeds max_bytes (' .. max_bytes .. ')', 0)\n"
  "    end\n"
  "    out[#out + 1] = chunk\n"
  "  end\n"
  "  return table.concat(out)\n"
  "end\n"
  "return M\n";

/* ---------- 缓冲区 ---------- */

static int buf_reserve(conn_t *c, size_t need)
{
  if (need <= c->cap) return 0;
  size_t nc = c->cap ? c->cap : 4096;
  while (nc < need) nc *= 2;
  char *nb = (char *)realloc(c->buf, nc);
  if (!nb) return -1;
  c->buf = nb;
  c->cap = nc;
  return 0;
}

static void buf_consume(conn_t *c, size_t n)
{
  if (n >= c->len) { c->len = 0; return; }
  memmove(c->buf, c->buf + n, c->len - n);
  c->len -= n;
}

static int append_body_buf(request_t *r, const char *data, size_t len)
{
  if (r->body_len + len > r->body_cap) {
    size_t nc = r->body_cap ? r->body_cap : 4096;
    while (nc < r->body_len + len) nc *= 2;
    char *nb = (char *)realloc(r->body_buf, nc);
    if (!nb) return -1;
    r->body_buf = nb;
    r->body_cap = nc;
  }
  if (len) memcpy(r->body_buf + r->body_len, data, len);
  r->body_len += len;
  return 0;
}

/* ---------- 头相关小工具 ---------- */

static const char *hdr_find(struct phr_header *h, size_t n, const char *name, size_t *vlen)
{
  size_t nl = strlen(name);
  for (size_t i = 0; i < n; i++) {
    if (!h[i].name) continue;
    if (h[i].name_len == nl && strncasecmp(h[i].name, name, nl) == 0) {
      if (vlen) *vlen = h[i].value_len;
      return h[i].value;
    }
  }
  return NULL;
}

/* 按逗号 token 判断 Connection 值是否包含某 token（大小写不敏感） */
static int conn_token_is(const char *v, size_t n, const char *token)
{
  size_t tl = strlen(token);
  size_t i = 0;
  while (i < n) {
    while (i < n && (v[i] == ',' || v[i] == ' ' || v[i] == '\t')) i++;
    size_t start = i;
    while (i < n && v[i] != ',') i++;
    size_t end = i;
    while (end > start && (v[end - 1] == ' ' || v[end - 1] == '\t')) end--;
    if (end - start == tl && strncasecmp(v + start, token, tl) == 0) return 1;
  }
  return 0;
}

static const char *reason_phrase(int status)
{
  switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    default: return "OK";
  }
}

/* Date 头每秒缓存一次 */
static const char *cached_date(void)
{
  static char buf[64];
  static time_t last = 0;
  time_t now = time(NULL);
  if (now != last) {
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    last = now;
  }
  return buf;
}

/* 用户响应头：过滤 C 自己生成的头、消毒 CR/LF、拒绝非法名 */
/* ---------- 异步日志（固定 nginx 风格） ---------- */

static void log_sink_maybe_flush(log_sink_t *s);
static void log_work_cb(uv_work_t *req);
static void log_after_cb(uv_work_t *req, int status);

static void log_write_file(log_sink_t *s, const char *data, size_t len)
{
  uv_mutex_lock(&s->io_mutex);
  int fd = open(s->path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) {
    fprintf(stderr, "log: open %s: %s\n", s->path, strerror(errno));
    uv_mutex_unlock(&s->io_mutex);
    return;
  }
  size_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, data + off, len - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      fprintf(stderr, "log: write %s: %s\n", s->path, strerror(errno));
      break;
    }
    off += (size_t)n;
  }
  if (off == len) s->bytes_since_rotate += len;
  close(fd);
  uv_mutex_unlock(&s->io_mutex);
}

static void log_sink_take(log_sink_t *s, char **out, size_t *out_len)
{
  uv_mutex_lock(&s->mutex);
  *out = s->pending;
  *out_len = s->pending_len;
  s->pending = NULL;
  s->pending_len = 0;
  s->pending_cap = 0;
  uv_mutex_unlock(&s->mutex);
}

static void log_work_cb(uv_work_t *req)
{
  log_sink_t *s = (log_sink_t *)req->data;
  char *data = NULL;
  size_t len = 0;
  log_sink_take(s, &data, &len);
  if (data && len) log_write_file(s, data, len);
  free(data);
}

/* ---- 线程池日志切分 ---- */
typedef struct {
  uv_work_t work;
  log_sink_t *sink;
  char err[256];
} log_rotate_t;

static void log_schedule_rotate(log_sink_t *s);
static void log_sink_request_rotate(log_sink_t *s);
static void log_rotate_work_cb(uv_work_t *req);
static void log_rotate_after_cb(uv_work_t *req, int status);

static void log_rotate_work_cb(uv_work_t *req)
{
  log_rotate_t *j = (log_rotate_t *)req->data;
  log_sink_t *s = j->sink;
  uv_mutex_lock(&s->io_mutex);
  if (s->rotate_keep <= 0) {
    if (truncate(s->path, 0) != 0) {
      snprintf(j->err, sizeof(j->err), "truncate %s: %s", s->path, strerror(errno));
    }
  } else {
    int keep = s->rotate_keep;
    char from[1024], to[1024];
    for (int i = keep - 1; i >= 1; i--) {
      snprintf(from, sizeof(from), "%s.%d", s->path, i);
      snprintf(to, sizeof(to), "%s.%d", s->path, i + 1);
      if (rename(from, to) != 0 && errno != ENOENT) {
        snprintf(j->err, sizeof(j->err), "rename %s: %s", from, strerror(errno));
      }
    }
    snprintf(to, sizeof(to), "%s.1", s->path);
    if (rename(s->path, to) != 0 && errno != ENOENT) {
      snprintf(j->err, sizeof(j->err), "rename %s: %s", s->path, strerror(errno));
    }
  }
  uv_mutex_unlock(&s->io_mutex);
}

static void log_rotate_after_cb(uv_work_t *req, int status)
{
  log_rotate_t *j = (log_rotate_t *)req->data;
  log_sink_t *s = j->sink;
  (void)status;
  s->rotate_in_flight = 0;
  s->bytes_since_rotate = 0;
  if (j->err[0] && !g_log_shutting_down) {
    log_error(LOG_WARN, "log rotate %s: %s", s->path, j->err);
  }
  free(j);
}

static void log_schedule_rotate(log_sink_t *s)
{
  if (!s->enabled || g_log_shutting_down || s->rotate_in_flight) return;
  log_rotate_t *j = (log_rotate_t *)calloc(1, sizeof(*j));
  if (!j) return;
  j->sink = s;
  j->work.data = j;
  s->rotate_in_flight = 1;
  if (uv_queue_work(loop, &j->work, log_rotate_work_cb, log_rotate_after_cb) != 0) {
    s->rotate_in_flight = 0;
    free(j);
    fprintf(stderr, "log: uv_queue_work rotate failed\n");
  }
}

static void log_rotate_timer_cb(uv_timer_t *t)
{
  log_sink_request_rotate((log_sink_t *)t->data);
}

/* 切分前先把内存队列写完，避免旧行落到新文件 */
static void log_sink_request_rotate(log_sink_t *s)
{
  if (!s->enabled || g_log_shutting_down || s->rotate_in_flight) return;
  s->rotate_requested = 1;
  if (s->in_flight || s->pending_len > 0) {
    log_sink_maybe_flush(s);
    return;
  }
  s->rotate_requested = 0;
  log_schedule_rotate(s);
}

static void log_after_cb(uv_work_t *req, int status)
{
  log_sink_t *s = (log_sink_t *)req->data;
  (void)status;
  s->in_flight = 0;
  if (g_log_shutting_down) return;
  if (s->rotate_requested || (s->rotate_size && s->bytes_since_rotate >= s->rotate_size)) {
    log_sink_request_rotate(s);
  }
  log_sink_maybe_flush(s);
}

static void log_sink_append(log_sink_t *s, const char *data, size_t len)
{
  if (!s->enabled || g_log_shutting_down) return;
  int schedule = 0;

  uv_mutex_lock(&s->mutex);
  if (len > s->max_bytes || s->pending_len > s->max_bytes - len) {
    s->dropped++;
  } else {
    if (s->pending_len + len > s->pending_cap) {
      size_t nc = s->pending_cap ? s->pending_cap : 4096;
      while (nc < s->pending_len + len) nc <<= 1;
      char *np = (char *)realloc(s->pending, nc);
      if (!np) {
        s->dropped++;
        goto out;
      }
      s->pending = np;
      s->pending_cap = nc;
    }
    memcpy(s->pending + s->pending_len, data, len);
    s->pending_len += len;
  }
out:
  if (!s->in_flight && s->pending_len >= 64 * 1024) {
    s->in_flight = 1;
    schedule = 1;
  }
  uv_mutex_unlock(&s->mutex);

  if (schedule) {
    if (uv_queue_work(loop, &s->work, log_work_cb, log_after_cb) != 0) {
      s->in_flight = 0;
      fprintf(stderr, "log: uv_queue_work failed\n");
    }
  }
}

static void log_sink_maybe_flush(log_sink_t *s)
{
  if (!s->enabled || g_log_shutting_down || s->in_flight) return;
  uv_mutex_lock(&s->mutex);
  int has = s->pending_len > 0;
  if (has) s->in_flight = 1;
  uv_mutex_unlock(&s->mutex);
  if (!has) return;
  if (uv_queue_work(loop, &s->work, log_work_cb, log_after_cb) != 0) {
    s->in_flight = 0;
    fprintf(stderr, "log: uv_queue_work failed\n");
  }
}

static void log_timer_cb(uv_timer_t *t)
{
  log_sink_maybe_flush((log_sink_t *)t->data);
}

static void log_sink_init(log_sink_t *s, const char *path, size_t max_bytes,
                          int interval_ms, int rotate_ms, size_t rotate_size,
                          int rotate_keep)
{
  if (!path || !path[0]) return;
  snprintf(s->path, sizeof(s->path), "%s", path);
  s->max_bytes = max_bytes ? max_bytes : (4 * 1024 * 1024);
  s->rotate_size = rotate_size;
  s->rotate_keep = rotate_keep;
  s->rotate_interval_ms = rotate_ms;
  s->work.data = s;
  s->timer.data = s;
  s->rotate_timer.data = s;
  s->enabled = 1;
  uv_mutex_init(&s->mutex);
  uv_mutex_init(&s->io_mutex);
  uv_timer_init(loop, &s->timer);
  uv_timer_start(&s->timer, log_timer_cb, (uint64_t)interval_ms, (uint64_t)interval_ms);
  if (rotate_ms > 0) {
    uv_timer_init(loop, &s->rotate_timer);
    uv_timer_start(&s->rotate_timer, log_rotate_timer_cb,
                   (uint64_t)rotate_ms, (uint64_t)rotate_ms);
  }
}

static void log_sink_flush_sync(log_sink_t *s)
{
  if (!s->enabled) return;
  char *data = NULL;
  size_t len = 0;
  log_sink_take(s, &data, &len);
  if (data && len) log_write_file(s, data, len);
  free(data);
}

static void log_init(void)
{
  log_sink_init(&g_access_log, g_log_access_path, g_log_max_bytes, g_log_flush_ms,
                g_log_rotate_ms, g_log_rotate_size, g_log_rotate_keep);
  log_sink_init(&g_error_log, g_log_error_path, g_log_max_bytes, g_log_flush_ms,
                g_log_rotate_ms, g_log_rotate_size, g_log_rotate_keep);
  g_log_inited = 1;
}

static void log_shutdown(void)
{
  g_log_shutting_down = 1;
  if (g_access_log.enabled) {
    uv_timer_stop(&g_access_log.timer);
    if (g_access_log.rotate_interval_ms > 0) uv_timer_stop(&g_access_log.rotate_timer);
  }
  if (g_error_log.enabled) {
    uv_timer_stop(&g_error_log.timer);
    if (g_error_log.rotate_interval_ms > 0) uv_timer_stop(&g_error_log.rotate_timer);
  }
  for (int i = 0; i < 200 &&
       (g_access_log.in_flight || g_error_log.in_flight ||
        g_access_log.rotate_in_flight || g_error_log.rotate_in_flight); i++) {
    uv_run(loop, UV_RUN_NOWAIT);
    usleep(10000);
  }
  log_sink_flush_sync(&g_access_log);
  log_sink_flush_sync(&g_error_log);
}

static void log_error(int level, const char *fmt, ...)
{
  if (level > g_log_level) return;
  char msg[2048];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  for (char *p = msg; *p; p++) {
    if (*p == '\n' || *p == '\r') *p = ' ';
  }

  time_t now = time(NULL);
  struct tm tm;
  localtime_r(&now, &tm);
  static const char *names[] = { "error", "warn", "info", "debug" };
  int lv = (level >= LOG_ERROR && level <= LOG_DEBUG) ? level : LOG_ERROR;
  char line[2300];
  snprintf(line, sizeof(line), "%04d/%02d/%02d %02d:%02d:%02d [%s] %d#%lu: %s\n",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec, names[lv],
           (int)getpid(), (unsigned long)uv_thread_self(), msg);

  if (g_error_log.enabled) {
    log_sink_append(&g_error_log, line, strlen(line));
  } else {
    fputs(line, stderr);
  }
}

/* ---- access log（固定 nginx combined 格式） ---- */
typedef struct {
  char *p;
  size_t len;
  size_t cap;
} sbuf_t;

static int sbuf_reserve(sbuf_t *b, size_t extra)
{
  if (b->len + extra <= b->cap) return 0;
  size_t nc = b->cap ? b->cap : 256;
  while (nc < b->len + extra) nc <<= 1;
  char *np = (char *)realloc(b->p, nc);
  if (!np) return -1;
  b->p = np;
  b->cap = nc;
  return 0;
}

static void sbuf_append(sbuf_t *b, const char *s, size_t n)
{
  if (sbuf_reserve(b, n) != 0) return;
  memcpy(b->p + b->len, s, n);
  b->len += n;
}

static void sbuf_putc(sbuf_t *b, char c)
{
  sbuf_append(b, &c, 1);
}

static void sbuf_printf(sbuf_t *b, const char *fmt, ...)
{
  char tmp[256];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (n < 0) return;
  if ((size_t)n >= sizeof(tmp)) n = (int)sizeof(tmp) - 1;
  sbuf_append(b, tmp, (size_t)n);
}

static void sbuf_escape(sbuf_t *b, const char *s, size_t n)
{
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '"' || c == '\\') {
      sbuf_putc(b, '\\');
      sbuf_putc(b, (char)c);
    } else if (c < 0x20 || c == 0x7f) {
      sbuf_printf(b, "\\x%02x", c);
    } else {
      sbuf_putc(b, (char)c);
    }
  }
}

static void log_access(conn_t *c)
{
  request_t *r = &c->req;
  if (r->access_logged || !g_access_log.enabled) return;
  if (!r->method && !r->head_copy && r->status == 0) return;
  r->access_logged = 1;

  char timebuf[64];
  time_t now = time(NULL);
  struct tm tm;
  localtime_r(&now, &tm);
  strftime(timebuf, sizeof(timebuf), "%d/%b/%Y:%H:%M:%S %z", &tm);

  int status = r->status ? r->status : (r->head_sent ? 200 : 499);
  size_t ref_len = 0, ua_len = 0;
  const char *ref = hdr_find(r->headers, r->num_headers, "referer", &ref_len);
  const char *ua = hdr_find(r->headers, r->num_headers, "user-agent", &ua_len);

  sbuf_t b = { 0 };
  sbuf_printf(&b, "%s - - [%s] \"",
              c->remote_addr[0] ? c->remote_addr : "-", timebuf);
  if (r->method && r->target) {
    sbuf_escape(&b, r->method, r->method_len);
    sbuf_putc(&b, ' ');
    sbuf_escape(&b, r->target, r->target_len);
    sbuf_printf(&b, " HTTP/1.%d", r->minor);
  } else {
    sbuf_putc(&b, '-');
  }
  sbuf_printf(&b, "\" %d %zu \"", status, r->written);
  if (ref) sbuf_escape(&b, ref, ref_len);
  else sbuf_putc(&b, '-');
  sbuf_append(&b, "\" \"", 3);
  if (ua) sbuf_escape(&b, ua, ua_len);
  else sbuf_putc(&b, '-');
  sbuf_append(&b, "\"\n", 2);

  if (b.p) log_sink_append(&g_access_log, b.p, b.len);
  free(b.p);
}

static size_t append_header(char *dst, size_t room, const char *name, const char *value)
{
  if (!name || !value || room < 8) return 0;
  if (strpbrk(name, "\r\n: \t")) return 0;
  if (strcasecmp(name, "content-length") == 0 ||
      strcasecmp(name, "transfer-encoding") == 0 ||
      strcasecmp(name, "connection") == 0 ||
      strcasecmp(name, "server") == 0 ||
      strcasecmp(name, "date") == 0) {
    return 0;
  }
  int n = snprintf(dst, room, "%s: ", name);
  if (n < 0 || (size_t)n >= room) return 0;
  size_t written = (size_t)n;
  size_t vl = strlen(value);
  for (size_t i = 0; i < vl; i++) {
    if (written + 4 >= room) return 0;
    char ch = value[i];
    if (ch == '\r' || ch == '\n') ch = ' ';
    dst[written++] = ch;
  }
  if (written + 4 >= room) return 0;
  memcpy(dst + written, "\r\n", 2);
  return written + 2;
}

/* 从 Lua 表收集 header（数组 { {N,V}, ... } 或 map {N=V}），idx 为表的绝对栈索引 */
static size_t collect_headers(lua_State *lua, int idx, char *hbuf, size_t cap)
{
  size_t hlen = 0;
  if (!lua_istable(lua, idx)) return 0;
  int alen = (int)lua_objlen(lua, idx);
  for (int i = 1; i <= alen; i++) {
    lua_rawgeti(lua, idx, i);
    if (lua_istable(lua, -1)) {
      lua_rawgeti(lua, -1, 1);
      lua_rawgeti(lua, -2, 2);
      if (lua_isstring(lua, -2) && lua_isstring(lua, -1)) {
        if (hlen < cap) {
          hlen += append_header(hbuf + hlen, cap - hlen,
                                lua_tostring(lua, -2), lua_tostring(lua, -1));
        }
      }
      lua_pop(lua, 3);
    } else {
      lua_pop(lua, 1);
    }
  }
  lua_pushnil(lua);
  while (lua_next(lua, idx)) {
    if (lua_type(lua, -2) == LUA_TSTRING && lua_isstring(lua, -1) && hlen < cap) {
      hlen += append_header(hbuf + hlen, cap - hlen,
                            lua_tostring(lua, -2), lua_tostring(lua, -1));
    }
    lua_pop(lua, 1);
  }
  return hlen;
}

/* ---------- 连接关闭 ---------- */

static void request_reset(conn_t *c);
static void conn_maybe_free(conn_t *c);

static void request_free_buffers(request_t *r)
{
  free(r->head_copy);
  r->head_copy = NULL;
  free(r->body_buf);
  r->body_buf = NULL;
  r->body_len = 0;
  r->body_cap = 0;
}

static void on_conn_close(uv_handle_t *h)
{
  conn_t *c = (conn_t *)h->data;
  if (--c->pending_closes == 0) conn_maybe_free(c);
}

/* conn 只有在 handle/timer 的 close 回调全部完成、且所有在飞写回调结束后才释放 */
static void conn_maybe_free(conn_t *c)
{
  if (c->closing && c->pending_closes == 0 && c->pending_writes == 0) {
    conn_t **pp = &g_conns;
    while (*pp && *pp != c) pp = &(*pp)->next;
    if (*pp == c) {
      *pp = c->next;
      if (g_conn_count > 0) g_conn_count--;
    }
    if (c->tls) {
      mbedtls_ssl_free(&c->ssl);
      if (c->tls_gen) { tls_gen_unref(c->tls_gen); c->tls_gen = NULL; }
      free(c->tls_in);
      free(c->tls_out);
    }
    if (g_active_connections > 0) g_active_connections--;
    free(c->buf);
    free(c);
    if (g_shutdown_state == 1 && g_conn_count == 0) shutdown_complete();
  }
}

static void close_conn(conn_t *c)
{
  if (c->closing) return;
  log_access(c);
  /* 尽力发 close_notify；不等待对端，随后立即 close */
  if (c->tls && !c->tls_handshaking) {
    mbedtls_ssl_close_notify(&c->ssl);
    tls_flush_out(c);
  }
  c->closing = 1;
  uv_timer_stop(&c->timer);
  if (!c->read_paused) {
    c->read_paused = 1;
    uv_read_stop((uv_stream_t *)&c->handle);
  }
  if (c->req.co_ref != LUA_NOREF) {
    luaL_unref(L, LUA_REGISTRYINDEX, c->req.co_ref);
    c->req.co_ref = LUA_NOREF;
    c->req.co = NULL;
  }
  if (c->res_ref != LUA_NOREF) {
    luaL_unref(L, LUA_REGISTRYINDEX, c->res_ref);
    c->res_ref = LUA_NOREF;
  }
  request_free_buffers(&c->req);
  c->pending_closes = 2;
  uv_close((uv_handle_t *)&c->handle, on_conn_close);
  uv_close((uv_handle_t *)&c->timer, on_conn_close);
}

static void on_idle_timeout(uv_timer_t *t)
{
  close_conn((conn_t *)t->data);
}

/* ---------- 优雅退出 ---------- */

static int conn_is_idle(conn_t *c)
{
  return c->req.co_ref == LUA_NOREF && c->state == ST_HEAD;
}

static void close_all_conns(void)
{
  conn_t *c = g_conns;
  while (c) {
    conn_t *next = c->next;
    if (!c->closing) close_conn(c);
    c = next;
  }
}

static void shutdown_complete(void)
{
  if (g_shutdown_state >= 3) return;
  g_shutdown_state = 3;
  log_error(LOG_INFO, "shutdown: complete");
  uv_timer_stop(&g_shutdown_timer);
  uv_stop(loop);
}

static void shutdown_timeout_cb(uv_timer_t *t)
{
  (void)t;
  if (g_shutdown_state != 1) return;
  g_shutdown_state = 2;
  log_error(LOG_WARN, "shutdown: timeout, forcing %zu connection(s)", g_conn_count);
  close_all_conns();
  uv_stop(loop);
}

static void begin_graceful_shutdown(void)
{
  if (g_shutdown_state != 0) return;
  g_shutdown_state = 1;
  log_error(LOG_INFO, "shutdown: draining, %zu connection(s), timeout=%ums",
            g_conn_count, g_shutdown_timeout_ms);

  for (size_t i = 0; i < g_listener_count; i++) {
    uv_close((uv_handle_t *)&g_listeners[i].handle, NULL);
  }

  conn_t *c = g_conns;
  while (c) {
    conn_t *next = c->next;
    if (!c->closing) {
      if (conn_is_idle(c)) {
        close_conn(c);
      } else {
        /* 当前请求继续处理，但响应结束后关闭；不再复用连接 */
        c->req.ka = 0;
        c->req.finish_close_after = 1;
      }
    }
    c = next;
  }

  if (g_shutdown_timeout_ms > 0) {
    uv_timer_start(&g_shutdown_timer, shutdown_timeout_cb,
                   g_shutdown_timeout_ms, 0);
  }
  if (g_conn_count == 0) shutdown_complete();
}

static void force_shutdown(void)
{
  if (g_shutdown_state >= 3) return;
  if (g_shutdown_state == 0) {
    g_shutdown_state = 2;
    log_error(LOG_WARN, "shutdown: forced before draining");
  } else {
    g_shutdown_state = 2;
    log_error(LOG_WARN, "shutdown: forced");
  }
  close_all_conns();
  uv_stop(loop);
}

static void reset_timer(conn_t *c)
{
  if (c->closing || c->no_timeout || c->idle_timeout_ms == 0) return;
  uv_timer_start(&c->timer, on_idle_timeout, c->idle_timeout_ms, 0);
}

static size_t write_queue_size(conn_t *c)
{
  return uv_stream_get_write_queue_size((uv_stream_t *)&c->handle)
       + (c->tls ? c->tls_out_len : 0);
}

/* ---------- TLS 读写 ---------- */

static int tls_in_reserve(conn_t *c, size_t need)
{
  if (need <= c->tls_in_cap) return 0;
  size_t nc = c->tls_in_cap ? c->tls_in_cap : 4096;
  while (nc < need) nc *= 2;
  char *nb = (char *)realloc(c->tls_in, nc);
  if (!nb) return -1;
  c->tls_in = nb;
  c->tls_in_cap = nc;
  return 0;
}

/* mbedTLS send 回调：密文先进入 tls_out，由 tls_flush_out 交给 uv_write */
static int tls_send_cb(void *ctx, const unsigned char *buf, size_t len)
{
  conn_t *c = (conn_t *)ctx;
  if (c->closing || len > g_write_hard_limit ||
      c->tls_out_len > g_write_hard_limit - len) {
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  size_t need = c->tls_out_len + len;
  if (need > c->tls_out_cap) {
    size_t nc = c->tls_out_cap ? c->tls_out_cap : 4096;
    while (nc < need) nc *= 2;
    char *nb = (char *)realloc(c->tls_out, nc);
    if (!nb) return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    c->tls_out = nb;
    c->tls_out_cap = nc;
  }
  memcpy(c->tls_out + c->tls_out_len, buf, len);
  c->tls_out_len = need;
  return (int)len;
}

/* mbedTLS recv 回调：从 tls_in 取密文；没有数据就是 WANT_READ */
static int tls_recv_cb(void *ctx, unsigned char *buf, size_t len)
{
  conn_t *c = (conn_t *)ctx;
  if (c->tls_in_len == 0) return MBEDTLS_ERR_SSL_WANT_READ;
  size_t n = c->tls_in_len < len ? c->tls_in_len : len;
  memcpy(buf, c->tls_in, n);
  if (n < c->tls_in_len) {
    memmove(c->tls_in, c->tls_in + n, c->tls_in_len - n);
  }
  c->tls_in_len -= n;
  return (int)n;
}

static int tls_flush_out(conn_t *c)
{
  if (!c->tls || c->tls_out_len == 0) return 0;
  if (c->closing) { c->tls_out_len = 0; return -1; }
  size_t len = c->tls_out_len;
  write_req_t *w = (write_req_t *)malloc(sizeof(write_req_t) + len);
  if (!w) { c->tls_out_len = 0; return -1; }
  w->conn = c;
  memcpy(w->data, c->tls_out, len);
  uv_buf_t buf = uv_buf_init(w->data, (unsigned int)len);
  if (uv_write(&w->req, (uv_stream_t *)&c->handle, &buf, 1, on_write) != 0) {
    free(w);
    c->tls_out_len = 0;
    return -1;
  }
  c->pending_writes++;
  c->tls_out_len = 0;
  return 0;
}

/* 明文 → TLS 记录 → 密文 → uv_write */
static int tls_write_plain(conn_t *c, const char *data, size_t len)
{
  if (c->closing || c->tls_handshaking) return -1;
  size_t off = 0;
  while (off < len) {
    int rc = mbedtls_ssl_write(&c->ssl, (const unsigned char *)data + off, len - off);
    if (rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
      if (tls_flush_out(c) != 0) return -1;
      continue;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ) {
      tls_flush_out(c);
      close_conn(c);
      return -1;
    }
    if (rc < 0) {
      tls_flush_out(c);
      close_conn(c);
      return -1;
    }
    if (rc == 0) break;
    off += (size_t)rc;
    if (tls_flush_out(c) != 0) {
      close_conn(c);
      return -1;
    }
  }
  return 0;
}

/* 推进握手；握手完成后把已解密的明文喂给现有 HTTP 状态机 */
static void tls_pump(conn_t *c)
{
  if (c->closing) return;

  if (c->tls_handshaking) {
    int rc = mbedtls_ssl_handshake(&c->ssl);
    if (tls_flush_out(c) != 0) { close_conn(c); return; }
    if (rc == 0) {
      c->tls_handshaking = 0;
      c->idle_timeout_ms = g_idle_timeout_ms;
      reset_timer(c);
    } else if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
      return;
    } else {
      log_error(LOG_WARN, "tls handshake failed: -0x%04x", (unsigned)(-rc));
      close_conn(c);
      return;
    }
  }

  while (!c->closing) {
    if (buf_reserve(c, c->len + 16384) != 0) { close_conn(c); return; }
    int rc = mbedtls_ssl_read(&c->ssl, (unsigned char *)c->buf + c->len, 16384);
    if (rc > 0) {
      c->len += (size_t)rc;
      reset_timer(c);
      process_buffer(c);
      if (c->closing) break;
      if (c->read_paused) break;
      if (c->state == ST_DRAIN || c->state == ST_RESPONSE) break;
      continue;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) break;
    if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
    if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) { close_conn(c); break; }
    log_error(LOG_WARN, "tls read failed: -0x%04x", (unsigned)(-rc));
    close_conn(c);
    break;
  }
  if (!c->closing) tls_flush_out(c);
}

static int tls_conn_setup(conn_t *c)
{
  if (!g_tls_gen) return -1;
  tls_gen_ref(g_tls_gen);
  c->tls_gen = g_tls_gen;
  mbedtls_ssl_init(&c->ssl);
  if (mbedtls_ssl_setup(&c->ssl, &c->tls_gen->conf) != 0) {
    mbedtls_ssl_free(&c->ssl);
    tls_gen_unref(c->tls_gen);
    c->tls_gen = NULL;
    return -1;
  }
  mbedtls_ssl_set_bio(&c->ssl, c, tls_send_cb, tls_recv_cb, NULL);
  c->tls = 1;
  c->tls_handshaking = 1;
  c->idle_timeout_ms = g_handshake_timeout_ms;
  return 0;
}

/* ---------- 写入 ---------- */

static void on_write(uv_write_t *req, int status);

static int write_bytes(conn_t *c, const char *data, size_t len)
{
  if (c->closing) return -1;
  if (len == 0) return 0;
  if (c->tls) return tls_write_plain(c, data, len);
  write_req_t *w = (write_req_t *)malloc(sizeof(write_req_t) + len);
  if (!w) { close_conn(c); return -1; }
  w->conn = c;
  memcpy(w->data, data, len);
  uv_buf_t buf = uv_buf_init(w->data, (unsigned int)len);
  int r = uv_write(&w->req, (uv_stream_t *)&c->handle, &buf, 1, on_write);
  if (r != 0) { free(w); close_conn(c); return -1; }
  c->pending_writes++;
  return 0;
}

/* 发送响应头；has_cl 为 1 时用 Content-Length 模式，否则 1.1 chunked / 1.0 close */
static int send_head(conn_t *c, int status, const char *hdrs, size_t hlen,
                     int has_cl, size_t cl)
{
  request_t *r = &c->req;
  if (r->head_sent || c->closing) return -1;

  resp_mode_t mode;
  if (r->is_head || status == 204 || status == 304) {
    mode = RESP_CL;
    r->body_disabled = 1;
    if (!has_cl) cl = 0;
  } else if (has_cl) {
    mode = RESP_CL;
  } else if (r->minor >= 1) {
    mode = RESP_CHUNKED;
  } else {
    mode = RESP_CLOSE;
    r->finish_close_after = 1;
  }

  r->mode = mode;
  r->status = status;
  r->cl = (mode == RESP_CL) ? cl : 0;
  r->head_sent = 1;

  int keep_alive = r->ka && !r->finish_close_after;

  char head[MAX_RESP_HEAD];
  int hn = snprintf(head, sizeof(head),
                    "HTTP/1.1 %d %s\r\n"
                    "Server: luajit-httpd\r\n"
                    "Date: %s\r\n"
                    "%.*s",
                    status, reason_phrase(status), cached_date(),
                    hdrs ? (int)hlen : 0, hdrs ? hdrs : "");
  if (hn < 0 || (size_t)hn >= sizeof(head)) {
    log_error(LOG_ERROR, "response head too large");
    close_conn(c);
    return -1;
  }
  if (mode == RESP_CL) {
    hn += snprintf(head + hn, sizeof(head) - (size_t)hn, "Content-Length: %zu\r\n", cl);
  } else if (mode == RESP_CHUNKED) {
    hn += snprintf(head + hn, sizeof(head) - (size_t)hn, "Transfer-Encoding: chunked\r\n");
  }
  hn += snprintf(head + hn, sizeof(head) - (size_t)hn, "Connection: %s\r\n\r\n",
                 keep_alive ? "keep-alive" : "close");
  if (hn < 0 || (size_t)hn >= sizeof(head)) {
    close_conn(c);
    return -1;
  }
  return write_bytes(c, head, (size_t)hn);
}

static void send_body(conn_t *c, const char *data, size_t len);
static void send_finish(conn_t *c);
static void on_resume(conn_t *c, int rc);

/* 响应体（按模式编码） */
static void send_body(conn_t *c, const char *data, size_t len)
{
  request_t *r = &c->req;
  if (c->closing || r->finished) return;
  if (!r->head_sent) {
    if (send_head(c, 200, NULL, 0, 0, 0) != 0) return;
  }
  if (r->body_disabled || len == 0) return;

  if (r->mode == RESP_CL) {
    if (r->written + len > r->cl) {
      log_error(LOG_ERROR, "response over content-length: written=%zu + %zu > %zu",
                r->written, len, r->cl);
      r->finish_close_after = 1;
      return;
    }
    if (write_bytes(c, data, len) == 0) r->written += len;
  } else if (r->mode == RESP_CHUNKED) {
    size_t need = len + 32;
    char *tmp = (char *)malloc(need);
    if (!tmp) { close_conn(c); return; }
    int pn = snprintf(tmp, 32, "%zx\r\n", len);
    memcpy(tmp + pn, data, len);
    memcpy(tmp + pn + len, "\r\n", 2);
    if (write_bytes(c, tmp, (size_t)pn + len + 2) == 0) r->written += len;
    free(tmp);
  } else { /* RESP_CLOSE */
    if (write_bytes(c, data, len) == 0) r->written += len;
  }
}

static void send_finish(conn_t *c)
{
  request_t *r = &c->req;
  if (r->finished || c->closing) return;
  if (!r->head_sent) {
    if (send_head(c, 200, NULL, 0, 1, 0) != 0) return;
  }
  if (r->mode == RESP_CHUNKED) {
    if (!r->body_disabled) write_bytes(c, "0\r\n\r\n", 5);
  } else if (r->mode == RESP_CL) {
    if (r->written != r->cl) {
      log_error(LOG_ERROR, "response length mismatch: written=%zu cl=%zu",
                r->written, r->cl);
      r->finish_close_after = 1;
    }
  } else if (r->mode == RESP_CLOSE) {
    r->finish_close_after = 1;
  }
  r->finished = 1;
  c->state = ST_DRAIN;
  if (c->pending_writes == 0) {
    /* 理论上不会：head 至少写了一次。防御性收尾。 */
  }
}

/* 一次性响应（table 返回 / 错误路径）：head + body 合并成单次写 */
static void send_simple_response(conn_t *c, int status, const char *hdrs, size_t hlen,
                                 const char *body, size_t blen)
{
  request_t *r = &c->req;
  if (c->closing || r->head_sent) {
    close_conn(c);
    return;
  }
  int body_disabled = r->is_head || status == 204 || status == 304;
  if (body_disabled) blen = 0;

  r->mode = RESP_CL;
  r->status = status;
  r->cl = blen;
  r->written = blen;
  r->body_disabled = body_disabled;
  r->head_sent = 1;
  r->finished = 1;

  int keep_alive = r->ka && !r->finish_close_after;
  char head[MAX_RESP_HEAD];
  int hn = snprintf(head, sizeof(head),
                    "HTTP/1.1 %d %s\r\n"
                    "Server: luajit-httpd\r\n"
                    "Date: %s\r\n"
                    "%.*s"
                    "Content-Length: %zu\r\n"
                    "Connection: %s\r\n"
                    "\r\n",
                    status, reason_phrase(status), cached_date(),
                    hdrs ? (int)hlen : 0, hdrs ? hdrs : "",
                    blen, keep_alive ? "keep-alive" : "close");
  if (hn < 0 || (size_t)hn >= sizeof(head)) {
    log_error(LOG_ERROR, "response head too large");
    close_conn(c);
    return;
  }
  size_t total = (size_t)hn + blen;
  if (total > 0) {
    if (c->tls) {
      char *tmp = (char *)malloc(total);
      if (!tmp) { close_conn(c); return; }
      memcpy(tmp, head, (size_t)hn);
      if (blen) memcpy(tmp + hn, body, blen);
      int rc = tls_write_plain(c, tmp, total);
      free(tmp);
      if (rc != 0) {
        if (!c->closing) close_conn(c);
        return;
      }
    } else {
      write_req_t *w = (write_req_t *)malloc(sizeof(write_req_t) + total);
      if (!w) { close_conn(c); return; }
      w->conn = c;
      memcpy(w->data, head, (size_t)hn);
      if (blen) memcpy(w->data + hn, body, blen);
      uv_buf_t buf = uv_buf_init(w->data, (unsigned int)total);
      if (uv_write(&w->req, (uv_stream_t *)&c->handle, &buf, 1, on_write) != 0) {
        free(w);
        close_conn(c);
        return;
      }
      c->pending_writes++;
    }
  }
  c->state = ST_DRAIN;
  if (c->pending_writes == 0) request_finalize(c);
}

static void send_error(conn_t *c, int status, const char *msg)
{
  if (c->closing) return;
  /* 停止读，避免对同一缓冲重复报错 */
  if (!c->read_paused) {
    c->read_paused = 1;
    uv_read_stop((uv_stream_t *)&c->handle);
  }
  c->req.finish_close_after = 1;
  char body[160];
  int n = snprintf(body, sizeof(body), "%d %s\n", status, msg ? msg : reason_phrase(status));
  if (c->req.head_sent) {
    /* 头已发：只能断开 */
    close_conn(c);
    return;
  }
  send_simple_response(c, status, NULL, 0, body, (size_t)n);
}

/* ---------- Lua 业务调用 ---------- */

static void push_req_table(conn_t *c)
{
  request_t *r = &c->req;
  lua_State *co = r->co;
  lua_newtable(co);
  lua_pushlstring(co, r->method, r->method_len);
  lua_setfield(co, -2, "method");
  lua_pushlstring(co, r->path, r->path_len);
  lua_setfield(co, -2, "path");
  if (r->query_len) {
    lua_pushlstring(co, r->query, r->query_len);
    lua_setfield(co, -2, "query");
  }
  lua_newtable(co);
  for (size_t i = 0; i < r->num_headers; i++) {
    if (!r->headers[i].name) continue;
    lua_pushlstring(co, r->headers[i].name, r->headers[i].name_len);
    lua_pushlstring(co, r->headers[i].value, r->headers[i].value_len);
    lua_settable(co, -3);
  }
  lua_setfield(co, -2, "headers");
  /* 显式三态，避免 req.body == nil 同时表示“无 body”和“大 body” */
  lua_pushboolean(co, r->body_cl > 0);
  lua_setfield(co, -2, "has_body");
  lua_pushinteger(co, (lua_Integer)r->body_cl);
  lua_setfield(co, -2, "body_size");
  lua_pushboolean(co, r->body_cl > g_auto_buffer_body);
  lua_setfield(co, -2, "streaming");
  if (r->auto_buffer && r->body_cl > 0) {
    lua_pushlstring(co, r->body_buf ? r->body_buf : "", r->body_cl);
    lua_setfield(co, -2, "body");
  }
  /* req.read / req.text：Lua 协程函数 */
  lua_rawgeti(co, LUA_REGISTRYINDEX, stream_lib_ref);
  lua_getfield(co, -1, "read");
  lua_remove(co, -2);
  lua_setfield(co, -2, "read");
  lua_rawgeti(co, LUA_REGISTRYINDEX, stream_lib_ref);
  lua_getfield(co, -1, "text");
  lua_remove(co, -2);
  lua_setfield(co, -2, "text");
}

static int res_write_head(lua_State *lua);
static int res_write(lua_State *lua);
static int res_finish(lua_State *lua);
static int res_queue_size(lua_State *lua);
static int res_header_sent(lua_State *lua);
static int res_set_timeout(lua_State *lua);

/* 每连接创建一次 res 表；闭包 upvalue 指向 conn 内 request_t（地址固定），可跨请求复用 */
static void create_res_table(conn_t *c)
{
  request_t *r = &c->req;
  lua_newtable(L);

  lua_pushlightuserdata(L, r);
  lua_pushcclosure(L, res_write_head, 1);
  lua_setfield(L, -2, "write_head");

  lua_pushlightuserdata(L, r);
  lua_pushcclosure(L, res_write, 1);
  lua_setfield(L, -2, "write");

  lua_pushlightuserdata(L, r);
  lua_pushcclosure(L, res_finish, 1);
  lua_setfield(L, -2, "finish");

  lua_pushlightuserdata(L, r);
  lua_pushcclosure(L, res_queue_size, 1);
  lua_setfield(L, -2, "queue_size");

  lua_pushlightuserdata(L, r);
  lua_pushcclosure(L, res_header_sent, 1);
  lua_setfield(L, -2, "header_sent");

  lua_pushlightuserdata(L, r);
  lua_pushcclosure(L, res_set_timeout, 1);
  lua_setfield(L, -2, "set_timeout");

  lua_rawgeti(L, LUA_REGISTRYINDEX, stream_lib_ref);
  lua_getfield(L, -1, "drain");
  lua_remove(L, -2);
  lua_setfield(L, -2, "drain");

  c->res_ref = luaL_ref(L, LUA_REGISTRYINDEX);
}

/* 旧写法：handler 返回 table */
static void apply_table_response(conn_t *c)
{
  request_t *r = &c->req;
  lua_State *co = r->co;
  int idx = lua_gettop(co);
  if (!lua_istable(co, idx)) {
    send_error(c, 500, "handler must return a table or use res");
    return;
  }
  if (r->head_sent) {
    send_error(c, 500, "handler returned a table after streaming response");
    return;
  }
  int status = 200;
  lua_getfield(co, idx, "status");
  if (lua_isnumber(co, -1)) status = (int)lua_tonumber(co, -1);
  lua_pop(co, 1);

  char hbuf[MAX_RESP_HEAD];
  size_t hlen = 0;
  lua_getfield(co, idx, "headers");
  if (lua_istable(co, -1)) hlen = collect_headers(co, lua_gettop(co), hbuf, sizeof(hbuf));
  lua_pop(co, 1);

  const char *body = "";
  size_t blen = 0;
  lua_getfield(co, idx, "body");
  if (lua_isstring(co, -1)) body = lua_tolstring(co, -1, &blen);

  send_simple_response(c, status, hbuf, hlen, body, blen);
  lua_pop(co, 2); /* body + table */
}

static void start_handler(conn_t *c)
{
  request_t *r = &c->req;
  if (c->closing) return;

  lua_State *co = lua_newthread(L);
  r->co = co;
  r->co_ref = luaL_ref(L, LUA_REGISTRYINDEX);

  lua_rawgeti(co, LUA_REGISTRYINDEX, app_ref);
  if (!lua_isfunction(co, -1)) {
    lua_getfield(co, -1, "handle");
    lua_remove(co, -2);
  }
  if (!lua_isfunction(co, -1)) {
    lua_pop(co, 1);
    send_error(c, 500, "app.lua has no handle function");
    return;
  }
  push_req_table(c);
  lua_rawgeti(co, LUA_REGISTRYINDEX, c->res_ref);

  int rc = lua_resume(co, 2);
  on_resume(c, rc);
}

static void deliver_body(conn_t *c);

static void on_resume(conn_t *c, int rc)
{
  request_t *r = &c->req;
  if (c->closing) return;

  if (rc == LUA_YIELD) {
    const char *reason = lua_tostring(r->co, -1);
    lua_pop(r->co, 1);
    if (reason && strcmp(reason, "read") == 0) {
      r->waiting_read = 1;
      c->state = ST_BODY;
      deliver_body(c);
      return;
    }
    if (reason && strcmp(reason, "drain") == 0) {
      size_t q = write_queue_size(c);
      if (q <= g_write_low_water) {
        lua_pushboolean(r->co, 1);
        int rc2 = lua_resume(r->co, 1);
        on_resume(c, rc2);
      } else {
        r->waiting_drain = 1;
        c->state = ST_RESPONSE;
      }
      return;
    }
    send_error(c, 500, "invalid stream yield");
    return;
  }

  if (rc != 0) {
    log_error(LOG_ERROR, "handler error: %s", lua_tostring(r->co, -1));
    lua_pop(r->co, 1);
    send_error(c, 500, "handler failed");
    return;
  }

  /* 正常结束 */
  if (lua_istable(r->co, -1)) {
    apply_table_response(c);
  } else if (!r->finished) {
    if (!r->head_sent) send_head(c, 200, NULL, 0, 1, 0);
    send_finish(c);
  }
  lua_settop(r->co, 0);
}

/* ---------- res 方法（C 函数） ---------- */

static int res_write_head(lua_State *lua)
{
  request_t *r = (request_t *)lua_touserdata(lua, lua_upvalueindex(1));
  conn_t *c = r->c;
  if (r->head_sent) return luaL_error(lua, "response head already sent");

  int n = lua_gettop(lua);
  int status = 200;
  if (n >= 2 && lua_isnumber(lua, 2)) status = (int)lua_tointeger(lua, 2);

  char hbuf[MAX_RESP_HEAD];
  size_t hlen = 0;
  if (n >= 3 && lua_istable(lua, 3)) hlen = collect_headers(lua, 3, hbuf, sizeof(hbuf));

  int has_cl = 0;
  size_t cl = 0;
  if (n >= 4 && lua_isnumber(lua, 4)) {
    has_cl = 1;
    cl = (size_t)lua_tointeger(lua, 4);
  }
  if (send_head(c, status, hbuf, hlen, has_cl, cl) != 0) {
    return luaL_error(lua, "failed to send response head");
  }
  lua_pushboolean(lua, 1);
  return 1;
}

static int res_write(lua_State *lua)
{
  request_t *r = (request_t *)lua_touserdata(lua, lua_upvalueindex(1));
  conn_t *c = r->c;
  size_t len = 0;
  const char *data = luaL_checklstring(lua, 2, &len);

  if (r->finished) return luaL_error(lua, "write after finish");
  if (!r->head_sent) {
    if (send_head(c, 200, NULL, 0, 0, 0) != 0) return luaL_error(lua, "failed to send response head");
  }
  send_body(c, data, len);

  size_t q = write_queue_size(c);
  if (q > g_write_hard_limit) {
    close_conn(c);
    return luaL_error(lua, "write queue limit exceeded");
  }
  lua_pushboolean(lua, q < g_write_high_water);
  lua_pushinteger(lua, (lua_Integer)q);
  return 2;
}

static int res_finish(lua_State *lua)
{
  request_t *r = (request_t *)lua_touserdata(lua, lua_upvalueindex(1));
  conn_t *c = r->c;
  if (r->finished) return luaL_error(lua, "finish called twice");
  send_finish(c);
  lua_pushboolean(lua, 1);
  return 1;
}

static int res_queue_size(lua_State *lua)
{
  request_t *r = (request_t *)lua_touserdata(lua, lua_upvalueindex(1));
  lua_pushinteger(lua, (lua_Integer)write_queue_size(r->c));
  return 1;
}

static int res_header_sent(lua_State *lua)
{
  request_t *r = (request_t *)lua_touserdata(lua, lua_upvalueindex(1));
  lua_pushboolean(lua, r->head_sent);
  return 1;
}

/* Bun.serve 的 server.timeout(req, sec) 对应物：0 = 本请求不再受 idle 超时约束 */
static int res_set_timeout(lua_State *lua)
{
  request_t *r = (request_t *)lua_touserdata(lua, lua_upvalueindex(1));
  conn_t *c = r->c;
  if (c->closing) return 0;
  int sec = (int)luaL_optinteger(lua, 2, 0);
  if (sec < 0) sec = 0;
  if (sec > 255) sec = 255; /* 与 Bun 的上限一致 */
  if (sec == 0) {
    c->no_timeout = 1;
    uv_timer_stop(&c->timer);
  } else {
    c->no_timeout = 0;
    c->idle_timeout_ms = (unsigned)(sec * 1000);
    reset_timer(c);
  }
  return 0;
}

/* ---------- 请求体 ---------- */

static void deliver_body(conn_t *c)
{
  request_t *r = &c->req;
  while (r->waiting_read && !c->closing) {
    if (r->body_len > 0) {
      size_t n = r->body_len > BODY_DELIVER_CHUNK ? BODY_DELIVER_CHUNK : r->body_len;
      lua_pushlstring(r->co, r->body_buf, n);
      memmove(r->body_buf, r->body_buf + n, r->body_len - n);
      r->body_len -= n;
      r->body_delivered += n;
      r->waiting_read = 0;
      int rc = lua_resume(r->co, 1);
      on_resume(c, rc);
    } else if (r->body_received >= r->body_cl) {
      r->body_eof = 1;
      lua_pushnil(r->co);
      r->waiting_read = 0;
      int rc = lua_resume(r->co, 1);
      on_resume(c, rc);
    } else {
      break; /* 等更多数据 */
    }
  }
  if (c->read_paused && !c->closing && c->state == ST_BODY &&
      r->body_len < g_read_high_water) {
    c->read_paused = 0;
    uv_read_start((uv_stream_t *)&c->handle, alloc_cb, on_read);
  }
}

/* ---------- 请求头解析 ---------- */

static int try_parse_head(conn_t *c)
{
  request_t *r = &c->req;
  const char *method = NULL, *path = NULL;
  size_t method_len = 0, path_len = 0, num_headers = MAX_HEADERS;
  int minor = 0;

  int rc = phr_parse_request(c->buf, c->len,
                             &method, &method_len, &path, &path_len,
                             &minor, r->headers, &num_headers, 0);
  if (rc == -2) {
    if (c->len > g_max_head_size) send_error(c, 431, "header too large");
    return 0;
  }
  if (rc == -1) { send_error(c, 400, "bad request"); return 0; }
  size_t head_len = (size_t)rc;
  if (head_len > g_max_head_size) { send_error(c, 431, "header too large"); return 0; }

  /* 头部字节复制到 request 自己的内存，之后 buf 可自由移动 */
  r->head_copy = (char *)malloc(head_len);
  if (!r->head_copy) { close_conn(c); return 0; }
  memcpy(r->head_copy, c->buf, head_len);
  r->head_len = head_len;

  ptrdiff_t mo = method - c->buf;
  ptrdiff_t po = path - c->buf;
  r->method = r->head_copy + mo;
  r->method_len = method_len;
  r->path = r->head_copy + po;
  r->path_len = path_len;
  r->target = r->path;
  r->target_len = r->path_len;
  for (size_t i = 0; i < num_headers; i++) {
    if (r->headers[i].name) {
      ptrdiff_t no = r->headers[i].name - c->buf;
      ptrdiff_t vo = r->headers[i].value - c->buf;
      r->headers[i].name = r->head_copy + no;
      r->headers[i].value = r->head_copy + vo;
    }
  }
  r->num_headers = num_headers;
  r->minor = minor;

  /* path 剥离 query */
  const char *qm = (const char *)memchr(r->path, '?', r->path_len);
  if (qm) {
    r->query = qm + 1;
    r->query_len = r->path_len - (size_t)(r->query - r->path);
    r->path_len = (size_t)(qm - r->path);
  }

  if (minor >= 1 && !hdr_find(r->headers, num_headers, "host", NULL)) {
    send_error(c, 400, "missing Host");
    return 0;
  }
  if (hdr_find(r->headers, num_headers, "transfer-encoding", NULL)) {
    send_error(c, 400, "Transfer-Encoding not supported");
    return 0;
  }

  ssize_t cl = -1;
  int cl_bad = 0, n_cl = 0;
  for (size_t i = 0; i < num_headers; i++) {
    if (!r->headers[i].name) continue;
    if (r->headers[i].name_len == 14 &&
        strncasecmp(r->headers[i].name, "content-length", 14) == 0) {
      n_cl++;
      const char *v = r->headers[i].value;
      size_t vl = r->headers[i].value_len;
      if (vl == 0 || vl > 18) { cl_bad = 1; continue; }
      for (size_t j = 0; j < vl; j++)
        if (!isdigit((unsigned char)v[j])) { cl_bad = 1; break; }
      if (!cl_bad) cl = (ssize_t)strtoll(v, NULL, 10);
    }
  }
  if (n_cl > 1 || cl_bad) { send_error(c, 400, "invalid Content-Length"); return 0; }
  if (cl > 0 && (unsigned long long)cl > (unsigned long long)max_body_stream) {
    send_error(c, 413, "body too large");
    return 0;
  }
  r->body_cl = cl > 0 ? (size_t)cl : 0;
  r->auto_buffer = r->body_cl <= g_auto_buffer_body;
  r->is_head = (method_len == 4 && strncasecmp(r->method, "HEAD", 4) == 0);

  int ka = minor >= 1;
  size_t cvlen = 0;
  const char *cv = hdr_find(r->headers, num_headers, "connection", &cvlen);
  if (cv) {
    if (conn_token_is(cv, cvlen, "close")) ka = 0;
    else if (minor == 0 && conn_token_is(cv, cvlen, "keep-alive")) ka = 1;
  }
  r->ka = ka;

  buf_consume(c, head_len);

  if (r->auto_buffer && r->body_cl > 0) {
    c->state = ST_BODY; /* 等 body 收齐后启动协程 */
    return 1;
  }
  start_handler(c);
  return 1;
}

static int consume_body(conn_t *c)
{
  request_t *r = &c->req;

  size_t want = r->body_cl - r->body_received;
  size_t avail = c->len;
  if (want > avail) want = avail;

  if (want > 0) {
    if (r->discarding) {
      size_t n = want > BODY_DELIVER_CHUNK ? BODY_DELIVER_CHUNK : want;
      buf_consume(c, n);
      r->body_received += n;
    } else if (r->waiting_read) {
      size_t n = want > BODY_DELIVER_CHUNK ? BODY_DELIVER_CHUNK : want;
      lua_pushlstring(r->co, c->buf, n);
      buf_consume(c, n);
      r->body_received += n;
      r->body_delivered += n;
      r->waiting_read = 0;
      int rc = lua_resume(r->co, 1);
      on_resume(c, rc);
      if (c->closing) return 0;
    } else {
      if (append_body_buf(r, c->buf, want) != 0) { close_conn(c); return 0; }
      buf_consume(c, want);
      r->body_received += want;
      if (!r->auto_buffer && !c->read_paused && r->body_len >= g_read_high_water) {
        c->read_paused = 1;
        uv_read_stop((uv_stream_t *)&c->handle);
      }
    }
  }

  if (r->body_received >= r->body_cl) {
    r->body_eof = 1;
    if (r->discarding && g_shutdown_state != 0) {
      close_conn(c);
      return 0;
    }
    if (r->auto_buffer && c->state == ST_BODY) {
      start_handler(c); /* req.body 为完整串 */
      return 1;
    }
    if (r->waiting_read) {
      lua_pushnil(r->co);
      r->waiting_read = 0;
      int rc = lua_resume(r->co, 1);
      on_resume(c, rc);
    }
    return 1;
  }
  return 0;
}

/* ---------- 收尾 ---------- */

static void request_finalize(conn_t *c)
{
  request_t *r = &c->req;
  if (c->closing) return;
  log_access(c);
  if (g_shutdown_state != 0) {
    r->ka = 0;
    r->finish_close_after = 1;
  }

  if (r->finish_close_after || !r->ka) {
    close_conn(c);
    return;
  }

  /* 响应已发完但请求体还有剩余：丢弃掉才能复用连接 */
  if (r->body_received < r->body_cl) {
    r->discarding = 1;
    c->state = ST_BODY;
    if (!c->read_paused) {
      uv_read_start((uv_stream_t *)&c->handle, alloc_cb, on_read);
    }
    return;
  }

  request_reset(c);
  /* 缓冲里可能还有下一个 pipeline 请求 */
  if (c->len > 0) process_buffer(c);
}

static void request_reset(conn_t *c)
{
  request_t *r = &c->req;
  if (r->co_ref != LUA_NOREF) {
    luaL_unref(L, LUA_REGISTRYINDEX, r->co_ref);
    r->co_ref = LUA_NOREF;
  }
  request_free_buffers(r);
  memset(r, 0, sizeof(*r));
  r->c = c;
  r->co_ref = LUA_NOREF;
  c->no_timeout = 0;
  c->idle_timeout_ms = g_idle_timeout_ms;
  c->state = ST_HEAD;
  reset_timer(c);
}

/* ---------- libuv 回调 ---------- */

static void alloc_cb(uv_handle_t *handle, size_t suggested, uv_buf_t *buf)
{
  (void)handle;
  size_t n = suggested ? suggested : 4096;
  buf->base = (char *)malloc(n);
  buf->len = buf->base ? n : 0;
}

static void on_write(uv_write_t *req, int status)
{
  write_req_t *w = (write_req_t *)req;
  conn_t *c = w->conn;
  free(w);
  if (c->pending_writes > 0) c->pending_writes--;
  if (c->closing) {
    conn_maybe_free(c);
    return;
  }
  if (status < 0) {
    close_conn(c);
    return;
  }
  reset_timer(c);

  request_t *r = &c->req;
  if (r->waiting_drain && !c->closing) {
    size_t q = write_queue_size(c);
    if (q <= WRITE_LOW_WATER) {
      r->waiting_drain = 0;
      lua_pushboolean(r->co, 1);
      int rc = lua_resume(r->co, 1);
      on_resume(c, rc);
      if (c->closing) return;
    }
  }
  if (c->state == ST_DRAIN && c->pending_writes == 0 && !c->closing) {
    request_finalize(c);
  }
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
  conn_t *c = (conn_t *)stream->data;
  if (nread < 0) {
    free(buf->base);
    close_conn(c);
    return;
  }
  if (nread == 0) { free(buf->base); return; }
  if (c->tls) {
    if (tls_in_reserve(c, c->tls_in_len + (size_t)nread) != 0) {
      free(buf->base);
      close_conn(c);
      return;
    }
    memcpy(c->tls_in + c->tls_in_len, buf->base, (size_t)nread);
    c->tls_in_len += (size_t)nread;
    free(buf->base);
    reset_timer(c);
    tls_pump(c);
    return;
  }
  if (buf_reserve(c, c->len + (size_t)nread) != 0) {
    free(buf->base);
    close_conn(c);
    return;
  }
  memcpy(c->buf + c->len, buf->base, (size_t)nread);
  c->len += (size_t)nread;
  free(buf->base);
  reset_timer(c);
  process_buffer(c);
}

/* ---------- 主驱动 ---------- */

static void process_buffer(conn_t *c)
{
  while (!c->closing) {
    if (c->state == ST_HEAD) {
      if (!try_parse_head(c)) return; /* 等更多数据或已出错 */
      if (c->state != ST_HEAD) {
        /* 协程已启动：可能立即发响应/等 body/等 drain */
        if (c->state == ST_BODY) continue;
        return;
      }
      continue;
    }
    if (c->state == ST_BODY) {
      if (!consume_body(c)) return;
      if (c->state != ST_BODY) {
        if (c->state == ST_HEAD) continue; /* 收尾后可能回到解析下一个 */
        return;
      }
      if (!c->read_paused && c->len > 0) continue; /* 继续喂 body */
      return;
    }
    return;
  }
}

static void on_connection(uv_stream_t *server, int status)
{
  if (status < 0) {
    log_error(LOG_ERROR, "accept error: %s", uv_strerror(status));
    return;
  }
  listener_t *l = (listener_t *)server->data;
  conn_t *c = (conn_t *)calloc(1, sizeof(conn_t));
  if (!c) return;
  g_active_connections++;
  uv_tcp_init(loop, &c->handle);
  uv_timer_init(loop, &c->timer);
  c->handle.data = c;
  c->timer.data = c;
  c->req.c = c;
  c->req.co_ref = LUA_NOREF;
  c->res_ref = LUA_NOREF;
  c->state = ST_HEAD;
  c->idle_timeout_ms = g_idle_timeout_ms;
  c->next = g_conns;
  g_conns = c;
  g_conn_count++;
  if (l && l->tls) {
    if (tls_conn_setup(c) != 0) {
      close_conn(c);
      return;
    }
  }
  create_res_table(c);
  if (uv_accept(server, (uv_stream_t *)&c->handle) != 0 ||
      g_active_connections > g_max_connections ||
      g_shutdown_state != 0) {
    close_conn(c);
    return;
  }
  /* 流式响应会分多次小写；默认关闭 Nagle，避免延迟 ACK 造成 ~40ms 停顿 */
  uv_tcp_nodelay((uv_tcp_t *)&c->handle, g_tcp.nodelay ? 1 : 0);

  struct sockaddr_storage peer;
  int peer_len = sizeof(peer);
  if (uv_tcp_getpeername(&c->handle, (struct sockaddr *)&peer, &peer_len) == 0) {
    if (peer.ss_family == AF_INET) {
      uv_ip4_name((const struct sockaddr_in *)&peer, c->remote_addr,
                  sizeof(c->remote_addr));
    } else if (peer.ss_family == AF_INET6) {
      uv_ip6_name((const struct sockaddr_in6 *)&peer, c->remote_addr,
                  sizeof(c->remote_addr));
    }
  }

  if (g_tcp.keepalive) {
    int r = uv_tcp_keepalive_ex(&c->handle, 1, g_tcp.keepalive_delay,
                                g_tcp.keepalive_interval, g_tcp.keepalive_count);
    if (r != 0) {
      log_error(LOG_WARN, "tcp keepalive failed: %s", uv_strerror(r));
    }
  }

  if (g_tcp.user_timeout_ms || g_tcp.send_buffer || g_tcp.recv_buffer) {
    uv_os_fd_t fd;
    if (uv_fileno((uv_handle_t *)&c->handle, &fd) == 0) {
      int v;
#ifdef TCP_USER_TIMEOUT
      if (g_tcp.user_timeout_ms) {
        v = (int)g_tcp.user_timeout_ms;
        setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &v, sizeof(v));
      }
#endif
      if (g_tcp.send_buffer) {
        v = g_tcp.send_buffer;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v));
      }
      if (g_tcp.recv_buffer) {
        v = g_tcp.recv_buffer;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v));
      }
    }
  }

  reset_timer(c);
  uv_read_start((uv_stream_t *)&c->handle, alloc_cb, on_read);
  if (c->tls) tls_pump(c);
}

/* ---------- 初始化 ---------- */

/* ---------- 配置加载 ---------- */

static void die(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "config error: ");
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  exit(1);
}

static long long cfg_ll(lua_State *l, int idx, const char *k, long long def)
{
  long long v = def;
  lua_getfield(l, idx, k);
  if (lua_isnumber(l, -1)) v = (long long)lua_tointeger(l, -1);
  lua_pop(l, 1);
  return v;
}

static const char *cfg_str(lua_State *l, int idx, const char *k)
{
  const char *s = NULL;
  lua_getfield(l, idx, k);
  if (lua_isstring(l, -1)) s = lua_tostring(l, -1);
  lua_pop(l, 1);
  return s;
}

static int cfg_bool(lua_State *l, int idx, const char *k, int def)
{
  int v = def;
  lua_getfield(l, idx, k);
  if (lua_isboolean(l, -1)) v = lua_toboolean(l, -1);
  else if (lua_isnumber(l, -1)) v = lua_tointeger(l, -1) != 0;
  lua_pop(l, 1);
  return v;
}

static void add_listener(const char *host, int port, int tls)
{
  if (port < 0 || port > 65535) die("listen port out of range: %d", port);
  listener_t *n = (listener_t *)realloc(g_listeners, (g_listener_count + 1) * sizeof(listener_t));
  if (!n) die("out of memory for listeners");
  g_listeners = n;
  listener_t *l = &g_listeners[g_listener_count++];
  memset(l, 0, sizeof(*l));
  snprintf(l->host, sizeof(l->host), "%s", host && *host ? host : "0.0.0.0");
  l->port = port;
  l->tls = tls;
}

static void parse_listen_string(const char *s, int tls, int default_port)
{
  char host[128] = "0.0.0.0";
  int port = default_port;
  if (s[0] == '[') {
    const char *e = strchr(s, ']');
    if (!e) die("bad listen address: %s", s);
    size_t hl = (size_t)(e - s - 1);
    if (hl >= sizeof(host)) die("listen host too long: %s", s);
    memcpy(host, s + 1, hl);
    host[hl] = 0;
    if (e[1] == ':') port = atoi(e + 2);
  } else {
    const char *c = strrchr(s, ':');
    if (c && strchr(s, ':') == c) {
      size_t hl = (size_t)(c - s);
      if (hl >= sizeof(host)) die("listen host too long: %s", s);
      memcpy(host, s, hl);
      host[hl] = 0;
      port = atoi(c + 1);
    } else if (c) {
      /* 不带方括号的 IPv6 字面量（如 ::1），使用默认端口 */
      if (strlen(s) >= sizeof(host)) die("listen host too long: %s", s);
      snprintf(host, sizeof(host), "%s", s);
    } else {
      port = atoi(s);
    }
  }
  add_listener(host, port, tls);
}

static void parse_listen_entry(lua_State *l, int idx, int tls, int default_port)
{
  if (lua_isnumber(l, idx)) {
    add_listener("0.0.0.0", (int)lua_tointeger(l, idx), tls);
    return;
  }
  if (lua_isstring(l, idx)) {
    parse_listen_string(lua_tostring(l, idx), tls, default_port);
    return;
  }
  if (!lua_istable(l, idx)) die("listen entry must be string/number/table");

  lua_getfield(l, idx, "port");
  int has_port = lua_isnumber(l, -1);
  lua_pop(l, 1);

  if (has_port) {
    const char *host = cfg_str(l, idx, "host");
    int port = (int)cfg_ll(l, idx, "port", default_port);
    int ltls = cfg_bool(l, idx, "tls", tls);
    add_listener(host ? host : "0.0.0.0", port, ltls);
    return;
  }

  /* 数组形式 */
  lua_Integer n = (lua_Integer)lua_objlen(l, idx);
  for (lua_Integer i = 1; i <= n; i++) {
    lua_rawgeti(l, idx, i);
    parse_listen_entry(l, lua_gettop(l), tls, default_port);
    lua_pop(l, 1);
  }
}

static void parse_limits(lua_State *l, int sidx)
{
  lua_getfield(l, sidx, "limits");
  if (!lua_istable(l, -1)) { lua_pop(l, 1); return; }
  int li = lua_gettop(l);
  long long mb = cfg_ll(l, li, "max_body", -1);
  if (mb > 0) max_body_stream = (size_t)mb;

  lua_getfield(l, li, "idle_timeout");
  if (lua_isnumber(l, -1)) {
    long long sec = (long long)lua_tointeger(l, -1);
    if (sec < 0) sec = 0;
    g_idle_timeout_ms = (unsigned)(sec * 1000);
  }
  lua_pop(l, 1);

  lua_getfield(l, li, "shutdown_timeout");
  if (lua_isnumber(l, -1)) {
    long long sec = (long long)lua_tointeger(l, -1);
    if (sec < 0) sec = 0;
    if (sec > 86400) sec = 86400;
    g_shutdown_timeout_ms = (unsigned)(sec * 1000);
  }
  lua_pop(l, 1);

  long long mc = cfg_ll(l, li, "max_connections", -1);
  if (mc > 0) g_max_connections = (size_t)mc;
  lua_pop(l, 1);
}

static void parse_buffers(lua_State *l, int sidx)
{
  lua_getfield(l, sidx, "buffers");
  if (!lua_istable(l, -1)) { lua_pop(l, 1); return; }
  int bi = lua_gettop(l);
  long long v;
  if ((v = cfg_ll(l, bi, "max_head", -1)) > 0) g_max_head_size = (size_t)v;
  if ((v = cfg_ll(l, bi, "auto_buffer_body", -1)) > 0) g_auto_buffer_body = (size_t)v;
  if ((v = cfg_ll(l, bi, "read_high_water", -1)) > 0) g_read_high_water = (size_t)v;
  if ((v = cfg_ll(l, bi, "write_high_water", -1)) > 0) g_write_high_water = (size_t)v;
  if ((v = cfg_ll(l, bi, "write_low_water", -1)) >= 0) g_write_low_water = (size_t)v;
  if ((v = cfg_ll(l, bi, "write_hard_limit", -1)) > 0) g_write_hard_limit = (size_t)v;
  lua_pop(l, 1);

  if (g_max_head_size < 1024) die("buffers.max_head too small");
  if (g_auto_buffer_body > max_body_stream) g_auto_buffer_body = max_body_stream;
  if (g_write_low_water > g_write_high_water)
    die("buffers.write_low_water > write_high_water");
  if (g_write_high_water > g_write_hard_limit)
    die("buffers.write_high_water > write_hard_limit");
}

static void parse_tls(lua_State *l, int sidx)
{
  lua_getfield(l, sidx, "tls");
  if (!lua_istable(l, -1)) { lua_pop(l, 1); return; }
  int ti = lua_gettop(l);

  const char *s = cfg_str(l, ti, "cert");
  if (s) snprintf(g_tls_cert_path, sizeof(g_tls_cert_path), "%s", s);
  s = cfg_str(l, ti, "key");
  if (s) snprintf(g_tls_key_path, sizeof(g_tls_key_path), "%s", s);
  s = cfg_str(l, ti, "ca");
  if (s) snprintf(g_tls_ca_path, sizeof(g_tls_ca_path), "%s", s);

  s = cfg_str(l, ti, "min_version");
  if (s) {
    if (strcmp(s, "1.3") == 0) g_tls_min13 = 1;
    else if (strcmp(s, "1.2") == 0) g_tls_min13 = 0;
    else die("tls.min_version must be \"1.2\" or \"1.3\"");
  }
  g_tls_client_auth = cfg_bool(l, ti, "client_auth", 0);

  lua_getfield(l, ti, "handshake_timeout");
  if (lua_isnumber(l, -1)) {
    long long sec = (long long)lua_tointeger(l, -1);
    if (sec >= 0) g_handshake_timeout_ms = (unsigned)(sec * 1000);
  }
  lua_pop(l, 1);

  lua_getfield(l, ti, "check_interval");
  if (lua_isnumber(l, -1)) {
    double sec = lua_tonumber(l, -1);
    int ms = 0;
    if (sec > 0) {
      ms = (int)(sec * 1000);
      if (ms < 100) ms = 100;
      if (ms > 86400000) ms = 86400000;
    }
    g_tls_check_interval_ms = ms;
  }
  lua_pop(l, 1);

  lua_getfield(l, ti, "alpn");
  if (lua_istable(l, -1)) {
    int ai = lua_gettop(l);
    lua_Integer n = (lua_Integer)lua_objlen(l, ai);
    for (lua_Integer i = 1; i <= n && g_tls_alpn_count < 8; i++) {
      lua_rawgeti(l, ai, i);
      if (lua_isstring(l, -1)) {
        snprintf(g_tls_alpn_buf[g_tls_alpn_count],
                 sizeof(g_tls_alpn_buf[g_tls_alpn_count]), "%s", lua_tostring(l, -1));
        g_tls_alpn[g_tls_alpn_count] = g_tls_alpn_buf[g_tls_alpn_count];
        g_tls_alpn_count++;
      }
      lua_pop(l, 1);
    }
    g_tls_alpn[g_tls_alpn_count] = NULL;
  }
  lua_pop(l, 1);

  /* SNI: sni = { { server_name = "a.example.com", cert = "...", key = "...",
     ca = "...", client_auth = true }, ... } */
  for (size_t i = 0; i < MAX_SNI_CERTS; i++) {
    g_sni_ca_paths[i][0] = 0;
    g_sni_client_auth[i] = -1;
  }
  g_sni_count = 0;
  lua_getfield(l, ti, "sni");
  if (lua_istable(l, -1)) {
    int si = lua_gettop(l);
    lua_Integer n = (lua_Integer)lua_objlen(l, si);
    if (n > MAX_SNI_CERTS) die("tls.sni supports at most %d entries", MAX_SNI_CERTS);
    for (lua_Integer i = 1; i <= n; i++) {
      lua_rawgeti(l, si, i);
      if (!lua_istable(l, -1)) die("tls.sni[%d] must be a table", (int)i);
      int ei = lua_gettop(l);
      const char *name = cfg_str(l, ei, "server_name");
      const char *cert = cfg_str(l, ei, "cert");
      const char *key = cfg_str(l, ei, "key");
      const char *ca = cfg_str(l, ei, "ca");
      if (!name || !cert || !key) {
        die("tls.sni[%d] requires server_name/cert/key", (int)i);
      }
      if (strlen(name) >= sizeof(g_sni_names[0])) {
        die("tls.sni[%d].server_name too long", (int)i);
      }
      if (name[0] == '*' && !(name[1] == '.' && name[2] != 0)) {
        die("tls.sni[%d].server_name wildcard must be *.suffix", (int)i);
      }

      int cauth = -1;
      lua_getfield(l, ei, "client_auth");
      if (lua_isboolean(l, -1)) cauth = lua_toboolean(l, -1);
      lua_pop(l, 1);
      int eff = cauth >= 0 ? cauth : g_tls_client_auth;
      if (eff && !(ca && ca[0]) && !g_tls_ca_path[0]) {
        die("tls.sni[%d] client_auth requires ca (own or tls.ca)", (int)i);
      }

      snprintf(g_sni_names[g_sni_count], sizeof(g_sni_names[0]), "%s", name);
      snprintf(g_sni_cert_paths[g_sni_count], sizeof(g_sni_cert_paths[0]), "%s", cert);
      snprintf(g_sni_key_paths[g_sni_count], sizeof(g_sni_key_paths[0]), "%s", key);
      if (ca && ca[0]) {
        snprintf(g_sni_ca_paths[g_sni_count], sizeof(g_sni_ca_paths[0]), "%s", ca);
      }
      g_sni_client_auth[g_sni_count] = cauth;
      g_sni_count++;
      lua_pop(l, 1);
    }
  }
  lua_pop(l, 1);

  if (cfg_str(l, ti, "ciphers") || cfg_str(l, ti, "ciphersuites")) {
    log_error(LOG_WARN, "warning: tls.ciphers/ciphersuites not applied yet (using mbedTLS defaults)");
  }
  lua_pop(l, 1); /* tls */
}

static void tls_gen_free(tls_gen_t *g)
{
  if (!g) return;
  mbedtls_ssl_config_free(&g->conf);
  for (size_t i = 0; i < g->sni_count; i++) {
    mbedtls_x509_crt_free(&g->sni[i].cert);
    mbedtls_pk_free(&g->sni[i].key);
    if (g->sni[i].has_ca) mbedtls_x509_crt_free(&g->sni[i].ca);
  }
  free(g->sni);
  mbedtls_x509_crt_free(&g->default_cert);
  mbedtls_pk_free(&g->default_key);
  if (g->has_ca) mbedtls_x509_crt_free(&g->ca);
  mbedtls_ctr_drbg_free(&g->drbg);
  mbedtls_entropy_free(&g->entropy);
  free(g);
}

static void tls_gen_ref(tls_gen_t *g)
{
  if (g) g->refs++;
}

static void tls_gen_unref(tls_gen_t *g)
{
  if (g && --g->refs == 0) tls_gen_free(g);
}

static void tls_report(int ret, char *buf, size_t n)
{
  if (ret > 0) snprintf(buf, n, "%d certificate(s) failed to parse", ret);
  else mbedtls_strerror(ret, buf, n);
}

static void tls_msg(int fatal, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(tls_errbuf, sizeof(tls_errbuf), fmt, ap);
  va_end(ap);
  if (fatal) {
    log_error(LOG_ERROR, "tls: %s", tls_errbuf);
    exit(1);
  }
}

/* 服务端 SNI：精确名优先，其次 *.suffix 通配（只匹配一级标签） */
static int tls_apply_pair(mbedtls_ssl_context *ssl, tls_gen_t *g, tls_cert_pair_t *pair)
{
  int rc = mbedtls_ssl_set_hs_own_cert(ssl, &pair->cert, &pair->key);
  if (rc != 0) return rc;
  if (pair->has_ca) {
    mbedtls_ssl_set_hs_ca_chain(ssl, &pair->ca, NULL);
  } else if (g->has_ca) {
    mbedtls_ssl_set_hs_ca_chain(ssl, &g->ca, NULL);
  }
  mbedtls_ssl_set_hs_authmode(ssl, pair->client_auth
      ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
  return 0;
}

static int tls_sni_cb(void *p, mbedtls_ssl_context *ssl,
                      const unsigned char *name, size_t len)
{
  tls_gen_t *g = (tls_gen_t *)p;
  if (!g || len == 0 || len >= 128) return 0;
  char host[128];
  memcpy(host, name, len);
  host[len] = 0;

  for (size_t i = 0; i < g->sni_count; i++) {
    if (strcasecmp(host, g->sni[i].server_name) == 0) {
      return tls_apply_pair(ssl, g, &g->sni[i]);
    }
  }
  for (size_t i = 0; i < g->sni_count; i++) {
    const char *pat = g->sni[i].server_name;
    if (strncmp(pat, "*.", 2) != 0) continue;
    const char *suffix = pat + 2;
    size_t hl = strlen(host), sl = strlen(suffix);
    if (hl <= sl + 1 || host[hl - sl - 1] != '.') continue;
    if (strcasecmp(host + hl - sl, suffix) != 0) continue;
    /* 通配只匹配一级标签：a.example.com 可以，a.b.example.com 不行 */
    if (memchr(host, '.', hl - sl - 1) != NULL) continue;
    return tls_apply_pair(ssl, g, &g->sni[i]);
  }
  return 0; /* 使用默认证书 + 全局 mTLS 策略 */
}

/* ---------- 吊销表：存储 / 加载 / 验证 ---------- */

static uint64_t fp_hash(const uint8_t *k)
{
  uint64_t h = 0x9E3779B97F4A7C15ULL;
  for (int i = 0; i < 32; i++) {
    h ^= k[i];
    h *= 0x100000001B3ULL;
    h ^= h >> 29;
  }
  return h;
}

static revoked_store_t *revoked_store_new(size_t hint)
{
  size_t cap = 1024;
  while (cap < hint) cap <<= 1;
  revoked_store_t *s = (revoked_store_t *)calloc(1, sizeof(*s));
  if (!s) return NULL;
  s->keys = (uint8_t *)calloc(cap, 32);
  s->used = (uint8_t *)calloc(cap, 1);
  if (!s->keys || !s->used) {
    free(s->keys);
    free(s->used);
    free(s);
    return NULL;
  }
  s->cap = cap;
  return s;
}

static void revoked_store_free(revoked_store_t *s)
{
  if (!s) return;
  free(s->keys);
  free(s->used);
  free(s);
}

static int revoked_store_grow(revoked_store_t *s)
{
  size_t ncap = s->cap << 1;
  uint8_t *nkeys = (uint8_t *)calloc(ncap, 32);
  uint8_t *nused = (uint8_t *)calloc(ncap, 1);
  if (!nkeys || !nused) {
    free(nkeys);
    free(nused);
    return -1;
  }
  for (size_t i = 0; i < s->cap; i++) {
    if (!s->used[i]) continue;
    const uint8_t *fp = s->keys + i * 32;
    size_t j = (size_t)(fp_hash(fp) & (ncap - 1));
    while (nused[j]) j = (j + 1) & (ncap - 1);
    memcpy(nkeys + j * 32, fp, 32);
    nused[j] = 1;
  }
  free(s->keys);
  free(s->used);
  s->keys = nkeys;
  s->used = nused;
  s->cap = ncap;
  return 0;
}

static int revoked_store_contains(const revoked_store_t *s, const uint8_t *fp)
{
  size_t i = (size_t)(fp_hash(fp) & (s->cap - 1));
  while (s->used[i]) {
    if (memcmp(s->keys + i * 32, fp, 32) == 0) return 1;
    i = (i + 1) & (s->cap - 1);
  }
  return 0;
}

static int revoked_store_insert(revoked_store_t *s, const uint8_t *fp)
{
  if (revoked_store_contains(s, fp)) return 0;
  if ((s->count + 1) * 10 > s->cap * 7) {
    if (revoked_store_grow(s) != 0) return -1;
  }
  size_t i = (size_t)(fp_hash(fp) & (s->cap - 1));
  while (s->used[i]) i = (i + 1) & (s->cap - 1);
  memcpy(s->keys + i * 32, fp, 32);
  s->used[i] = 1;
  s->count++;
  return 0;
}

/* 返回 1=解析成功，0=空行/注释，-1=非法 */
static int revocation_parse_line(const char *line, uint8_t out[32])
{
  size_t n = strlen(line);
  while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r' ||
                   line[n - 1] == ' ' || line[n - 1] == '\t')) n--;
  size_t i = 0;
  while (i < n && isspace((unsigned char)line[i])) i++;
  if (i == n || line[i] == '#') return 0;
  if (line[i] == '0' && i + 1 < n && (line[i + 1] == 'x' || line[i + 1] == 'X')) i += 2;

  unsigned char buf[32];
  size_t digits = 0;
  for (; i < n; i++) {
    char ch = line[i];
    if (ch == ':' || ch == ' ' || ch == '\t') continue;
    int v;
    if (ch >= '0' && ch <= '9') v = ch - '0';
    else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
    else return -1;
    if (digits >= 64) return -1;
    if ((digits & 1) == 0) buf[digits / 2] = (unsigned char)(v << 4);
    else buf[digits / 2] |= (unsigned char)v;
    digits++;
  }
  if (digits == 0) return 0;
  if (digits != 64) return -1;
  memcpy(out, buf, 32);
  return 1;
}

static revoked_store_t *revocation_load_file(const char *path, char *err, size_t errlen)
{
  if (err && errlen) err[0] = 0;
  FILE *f = fopen(path, "r");
  if (!f) {
    if (err) snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno));
    return NULL;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    if (err) snprintf(err, errlen, "cannot stat %s", path);
    fclose(f);
    return NULL;
  }
  long sz = ftell(f);
  if (sz < 0 || (size_t)sz > g_revocation.max_bytes) {
    if (err) snprintf(err, errlen, "%s too large (max %zu bytes)", path, g_revocation.max_bytes);
    fclose(f);
    return NULL;
  }
  fseek(f, 0, SEEK_SET);

  revoked_store_t *s = revoked_store_new(1024);
  if (!s) {
    if (err) snprintf(err, errlen, "out of memory");
    fclose(f);
    return NULL;
  }

  char line[256];
  int bad = 0;
  while (fgets(line, sizeof(line), f)) {
    size_t ll = strlen(line);
    if (ll == sizeof(line) - 1 && line[ll - 1] != '\n') { bad = 1; break; }
    uint8_t fp[32];
    int r = revocation_parse_line(line, fp);
    if (r == 0) continue;
    if (r < 0) { bad = 1; break; }
    if (s->count >= g_revocation.max_entries) { bad = 1; break; }
    if (revoked_store_insert(s, fp) != 0) { bad = 1; break; }
  }
  if (ferror(f)) bad = 1;
  fclose(f);

  if (bad) {
    if (err) snprintf(err, errlen, "invalid data in %s", path);
    revoked_store_free(s);
    return NULL;
  }
  return s;
}

/* 线程池刷新：后台构建新表，完成后主线程切换指针（A/B） */
typedef struct {
  uv_work_t work;
  revoked_store_t *store;
  char err[512];
} revocation_job_t;

static void revocation_work_cb(uv_work_t *req)
{
  revocation_job_t *j = (revocation_job_t *)req->data;
  j->store = revocation_load_file(g_revocation.source_file, j->err, sizeof(j->err));
}

static void revocation_after_cb(uv_work_t *req, int status)
{
  revocation_job_t *j = (revocation_job_t *)req->data;
  (void)status;
  g_revocation_checking = 0;
  if (j->store) {
    revoked_store_t *old = g_revoked;
    g_revoked = j->store;
    g_revocation.loaded = 1;
    revoked_store_free(old);
    log_error(LOG_INFO, "revocation: loaded %zu entries (periodic)", j->store->count);
  } else {
    log_error(LOG_ERROR, "revocation: periodic refresh failed: %s", j->err);
  }
  free(j);
}

static void revocation_timer_cb(uv_timer_t *t)
{
  (void)t;
  if (!g_revocation.enabled || g_revocation_checking) return;
  revocation_job_t *j = (revocation_job_t *)calloc(1, sizeof(*j));
  if (!j) return;
  j->work.data = j;
  g_revocation_checking = 1;
  if (uv_queue_work(loop, &j->work, revocation_work_cb, revocation_after_cb) != 0) {
    g_revocation_checking = 0;
    free(j);
    log_error(LOG_ERROR, "revocation: uv_queue_work refresh failed");
  }
}

static void revocation_init(void)
{
  if (!g_revocation.enabled) return;
  if (!g_revocation.source_file[0]) {
    log_error(LOG_ERROR, "revocation: no provider file configured");
    return;
  }
  if (!g_revocation.load_on_start) {
    log_error(LOG_INFO, "revocation: load_on_start=false, table empty until first periodic refresh");
    return;
  }
  char err[512] = "";
  revoked_store_t *ns = revocation_load_file(g_revocation.source_file, err, sizeof(err));
  if (!ns) {
    log_error(LOG_ERROR, "revocation: initial load failed: %s", err);
    return;
  }
  g_revoked = ns;
  g_revocation.loaded = 1;
  log_error(LOG_INFO, "revocation: loaded %zu entries", ns->count);
}

/* mbedTLS 证书验证回调：只检查客户端叶子证书（depth 0） */
static int revocation_verify(void *p, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
  (void)p;
  if (!g_revocation.enabled || depth != 0) return 0;
  if (!g_revocation.loaded) {
    if (g_revocation.reject_all) *flags |= MBEDTLS_X509_BADCERT_REVOKED;
    return 0;
  }
  if (!g_revoked) return 0;
  uint8_t fp[32];
  if (mbedtls_sha256(crt->raw.p, crt->raw.len, fp, 0) != 0) return 0;
  if (revoked_store_contains(g_revoked, fp)) {
    *flags |= MBEDTLS_X509_BADCERT_REVOKED;
  }
  return 0;
}

static tls_gen_t *tls_gen_build(int fatal)
{
  int ret;
  char err[128];
  tls_gen_t *g = (tls_gen_t *)calloc(1, sizeof(*g));
  if (!g) { tls_msg(fatal, "out of memory"); return NULL; }

  mbedtls_ssl_config_init(&g->conf);
  mbedtls_x509_crt_init(&g->default_cert);
  mbedtls_pk_init(&g->default_key);
  mbedtls_entropy_init(&g->entropy);
  mbedtls_ctr_drbg_init(&g->drbg);

  const char *pers = "luajit-httpd";
  ret = mbedtls_ctr_drbg_seed(&g->drbg, mbedtls_entropy_func, &g->entropy,
                              (const unsigned char *)pers, strlen(pers));
  if (ret != 0) {
    tls_report(ret, err, sizeof(err));
    tls_msg(fatal, "ctr_drbg_seed: %s", err);
    goto fail;
  }

  ret = mbedtls_x509_crt_parse_file(&g->default_cert, g_tls_cert_path);
  if (ret != 0) {
    tls_report(ret, err, sizeof(err));
    tls_msg(fatal, "cannot load cert %s: %s", g_tls_cert_path, err);
    goto fail;
  }
  ret = mbedtls_pk_parse_keyfile(&g->default_key, g_tls_key_path, NULL, NULL, NULL);
  if (ret != 0) {
    tls_report(ret, err, sizeof(err));
    tls_msg(fatal, "cannot load key %s: %s", g_tls_key_path, err);
    goto fail;
  }

  if (g_tls_ca_path[0]) {
    mbedtls_x509_crt_init(&g->ca);
    g->has_ca = 1;
    ret = mbedtls_x509_crt_parse_file(&g->ca, g_tls_ca_path);
    if (ret != 0) {
      tls_report(ret, err, sizeof(err));
      tls_msg(fatal, "cannot load ca %s: %s", g_tls_ca_path, err);
      goto fail;
    }
  } else if (g_tls_client_auth) {
    tls_msg(fatal, "client_auth requires tls.ca");
    goto fail;
  }

  if (g_sni_count) {
    g->sni = (tls_cert_pair_t *)calloc(g_sni_count, sizeof(tls_cert_pair_t));
    if (!g->sni) { tls_msg(fatal, "out of memory for sni certs"); goto fail; }
    g->sni_count = g_sni_count;
    for (size_t i = 0; i < g->sni_count; i++) {
      mbedtls_x509_crt_init(&g->sni[i].cert);
      mbedtls_pk_init(&g->sni[i].key);
    }
    for (size_t i = 0; i < g->sni_count; i++) {
      snprintf(g->sni[i].server_name, sizeof(g->sni[i].server_name), "%s",
               g_sni_names[i]);
      ret = mbedtls_x509_crt_parse_file(&g->sni[i].cert, g_sni_cert_paths[i]);
      if (ret != 0) {
        tls_report(ret, err, sizeof(err));
        tls_msg(fatal, "cannot load sni cert %s: %s", g_sni_cert_paths[i], err);
        goto fail;
      }
      ret = mbedtls_pk_parse_keyfile(&g->sni[i].key, g_sni_key_paths[i],
                                     NULL, NULL, NULL);
      if (ret != 0) {
        tls_report(ret, err, sizeof(err));
        tls_msg(fatal, "cannot load sni key %s: %s", g_sni_key_paths[i], err);
        goto fail;
      }

      g->sni[i].client_auth = g_sni_client_auth[i] >= 0
          ? g_sni_client_auth[i] : g_tls_client_auth;
      if (g_sni_ca_paths[i][0]) {
        g->sni[i].has_ca = 1;
        mbedtls_x509_crt_init(&g->sni[i].ca);
        ret = mbedtls_x509_crt_parse_file(&g->sni[i].ca, g_sni_ca_paths[i]);
        if (ret != 0) {
          tls_report(ret, err, sizeof(err));
          tls_msg(fatal, "cannot load sni ca %s: %s", g_sni_ca_paths[i], err);
          goto fail;
        }
      }
      if (g->sni[i].client_auth && !g->sni[i].has_ca && !g->has_ca) {
        tls_msg(fatal, "tls.sni[%zu] client_auth requires ca", i);
        goto fail;
      }
    }
  }

  ret = mbedtls_ssl_config_defaults(&g->conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    tls_report(ret, err, sizeof(err));
    tls_msg(fatal, "ssl_config_defaults: %s", err);
    goto fail;
  }
  mbedtls_ssl_conf_rng(&g->conf, mbedtls_ctr_drbg_random, &g->drbg);
  mbedtls_ssl_conf_verify(&g->conf, revocation_verify, NULL);
  mbedtls_ssl_conf_min_tls_version(&g->conf,
      g_tls_min13 ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2);

  if (g->has_ca) mbedtls_ssl_conf_ca_chain(&g->conf, &g->ca, NULL);
  mbedtls_ssl_conf_authmode(&g->conf, g_tls_client_auth
      ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);

  ret = mbedtls_ssl_conf_own_cert(&g->conf, &g->default_cert, &g->default_key);
  if (ret != 0) {
    tls_report(ret, err, sizeof(err));
    tls_msg(fatal, "ssl_conf_own_cert: %s", err);
    goto fail;
  }
  if (g->sni_count) mbedtls_ssl_conf_sni(&g->conf, tls_sni_cb, g);
  if (g_tls_alpn_count) mbedtls_ssl_conf_alpn_protocols(&g->conf, g_tls_alpn);
  return g;

fail:
  if (fatal) exit(1);
  tls_gen_free(g);
  return NULL;
}

/* ---------- 证书定时检测（线程池，A/B 切换） ---------- */

static void tls_add_path(const char *p)
{
  if (!p || !p[0] || g_tls_path_count >= MAX_TLS_PATHS) return;
  snprintf(g_tls_paths[g_tls_path_count], sizeof(g_tls_paths[0]), "%s", p);
  g_tls_path_count++;
}

static void tls_collect_paths(void)
{
  g_tls_path_count = 0;
  tls_add_path(g_tls_cert_path);
  tls_add_path(g_tls_key_path);
  tls_add_path(g_tls_ca_path);
  for (size_t i = 0; i < g_sni_count; i++) {
    tls_add_path(g_sni_cert_paths[i]);
    tls_add_path(g_sni_key_paths[i]);
    tls_add_path(g_sni_ca_paths[i]);
  }
}

static int tls_stat_all(tls_stamp_t *out)
{
  for (size_t i = 0; i < g_tls_path_count; i++) {
    struct stat st;
    if (stat(g_tls_paths[i], &st) != 0) {
      out[i].valid = 0;
      return -1;
    }
    out[i].valid = 1;
    out[i].sec = st.st_mtim.tv_sec;
    out[i].nsec = st.st_mtim.tv_nsec;
  }
  return 0;
}

static int tls_stamps_equal(const tls_stamp_t *a, const tls_stamp_t *b)
{
  for (size_t i = 0; i < g_tls_path_count; i++) {
    if (!a[i].valid || !b[i].valid) return 0;
    if (a[i].sec != b[i].sec || a[i].nsec != b[i].nsec) return 0;
  }
  return 1;
}

static void tls_snapshot_init(void)
{
  if (!g_tls_enabled) return;
  tls_collect_paths();
  if (tls_stat_all(g_tls_stamps) != 0) {
    log_error(LOG_WARN, "tls: cannot stat certificate files at startup");
  }
}

typedef struct {
  uv_work_t work;
  int ok;
  int changed;
  char err[1024];
  tls_gen_t *new_gen;
  tls_stamp_t *new_stamps;
} tls_check_job_t;

static void tls_check_work_cb(uv_work_t *req)
{
  tls_check_job_t *j = (tls_check_job_t *)req->data;
  tls_stamp_t *st = (tls_stamp_t *)calloc(g_tls_path_count ? g_tls_path_count : 1,
                                          sizeof(tls_stamp_t));
  if (!st) {
    snprintf(j->err, sizeof(j->err), "out of memory");
    return;
  }
  if (tls_stat_all(st) != 0) {
    snprintf(j->err, sizeof(j->err), "stat certificate files failed");
    free(st);
    return;
  }
  if (tls_stamps_equal(g_tls_stamps, st)) {
    j->ok = 1;
    free(st);
    return;
  }
  tls_gen_t *ng = tls_gen_build(0);
  if (!ng) {
    snprintf(j->err, sizeof(j->err), "%s",
             tls_errbuf[0] ? tls_errbuf : "tls build failed");
    free(st);
    return;
  }
  j->ok = 1;
  j->changed = 1;
  j->new_gen = ng;
  j->new_stamps = st;
}

static void tls_check_after_cb(uv_work_t *req, int status)
{
  tls_check_job_t *j = (tls_check_job_t *)req->data;
  (void)status;
  g_tls_checking = 0;

  if (j->ok && j->changed) {
    tls_gen_ref(j->new_gen);
    tls_gen_t *old = g_tls_gen;
    g_tls_gen = j->new_gen;
    memcpy(g_tls_stamps, j->new_stamps, g_tls_path_count * sizeof(tls_stamp_t));
    if (old) tls_gen_unref(old);
    log_error(LOG_INFO, "tls: certificate change detected, reloaded automatically");
  } else if (!j->ok) {
    log_error(LOG_ERROR, "tls: periodic check failed: %s", j->err);
  }

  free(j->new_stamps);
  free(j);
}

static void tls_check_timer_cb(uv_timer_t *t)
{
  (void)t;
  if (g_tls_checking || !g_tls_enabled || g_tls_path_count == 0) return;
  tls_check_job_t *j = (tls_check_job_t *)calloc(1, sizeof(*j));
  if (!j) return;
  j->work.data = j;
  g_tls_checking = 1;
  if (uv_queue_work(loop, &j->work, tls_check_work_cb, tls_check_after_cb) != 0) {
    g_tls_checking = 0;
    free(j);
    log_error(LOG_ERROR, "tls: uv_queue_work check failed");
  }
}

static void parse_tcp(lua_State *l, int sidx)
{
  lua_getfield(l, sidx, "tcp");
  if (!lua_istable(l, -1)) { lua_pop(l, 1); return; }
  int ti = lua_gettop(l);

  g_tcp.nodelay = cfg_bool(l, ti, "nodelay", g_tcp.nodelay);
  g_tcp.keepalive = cfg_bool(l, ti, "keepalive", g_tcp.keepalive);
  g_tcp.reuse_port = cfg_bool(l, ti, "reuse_port", g_tcp.reuse_port);

  long long v;
  if ((v = cfg_ll(l, ti, "keepalive_delay", -1)) >= 0) g_tcp.keepalive_delay = (unsigned)v;
  if ((v = cfg_ll(l, ti, "keepalive_interval", -1)) >= 0) g_tcp.keepalive_interval = (unsigned)v;
  if ((v = cfg_ll(l, ti, "keepalive_count", -1)) >= 0) g_tcp.keepalive_count = (unsigned)v;
  if ((v = cfg_ll(l, ti, "user_timeout", -1)) >= 0) g_tcp.user_timeout_ms = (unsigned)v;
  if ((v = cfg_ll(l, ti, "backlog", -1)) >= 0) g_tcp.backlog = (int)v;
  if ((v = cfg_ll(l, ti, "send_buffer", -1)) >= 0) g_tcp.send_buffer = (int)v;
  if ((v = cfg_ll(l, ti, "recv_buffer", -1)) >= 0) g_tcp.recv_buffer = (int)v;
  lua_pop(l, 1);

  if (g_tcp.keepalive_delay < 1 || g_tcp.keepalive_delay > 86400)
    die("tcp.keepalive_delay out of range (1..86400 seconds)");
  if (g_tcp.keepalive_interval < 1 || g_tcp.keepalive_interval > 3600)
    die("tcp.keepalive_interval out of range (1..3600 seconds)");
  if (g_tcp.keepalive_count < 1 || g_tcp.keepalive_count > 100)
    die("tcp.keepalive_count out of range (1..100)");
  if (g_tcp.user_timeout_ms > 86400000u)
    die("tcp.user_timeout out of range (0..86400000 ms)");
  if (g_tcp.backlog < 16 || g_tcp.backlog > 65535)
    die("tcp.backlog out of range (16..65535)");
  if (g_tcp.send_buffer < 0 || g_tcp.recv_buffer < 0)
    die("tcp.send_buffer/tcp.recv_buffer must be >= 0");
}

static void parse_revocation(lua_State *l, int cfg)
{
  lua_getfield(l, cfg, "revocation");
  if (!lua_istable(l, -1)) { lua_pop(l, 1); return; }
  int ri = lua_gettop(l);

  g_revocation.enabled = cfg_bool(l, ri, "enabled", 0);
  const char *key = cfg_str(l, ri, "key");
  if (key && strcasecmp(key, "sha256") != 0) {
    die("revocation.key currently supports only sha256");
  }
  if (cfg_str(l, ri, "signal")) {
    log_error(LOG_WARN, "revocation.signal ignored; refresh is periodic");
  }
  g_revocation.load_on_start = cfg_bool(l, ri, "load_on_start", 1);

  long long v;
  lua_getfield(l, ri, "interval");
  if (lua_isnumber(l, -1)) {
    double sec = lua_tonumber(l, -1);
    int ms = 0;
    if (sec > 0) {
      ms = (int)(sec * 1000);
      if (ms < 100) ms = 100;
      if (ms > 86400000) ms = 86400000;
    }
    g_revocation.interval_ms = ms;
  }
  lua_pop(l, 1);

  if ((v = cfg_ll(l, ri, "max_bytes", 64LL * 1024 * 1024)) > 0) {
    g_revocation.max_bytes = (size_t)v;
  }
  if ((v = cfg_ll(l, ri, "max_entries", 500000)) > 0) {
    g_revocation.max_entries = (size_t)v;
  }

  const char *oe = cfg_str(l, ri, "on_error");
  if (oe) {
    if (strcasecmp(oe, "reject_all") == 0) g_revocation.reject_all = 1;
    else if (strcasecmp(oe, "keep") == 0) g_revocation.reject_all = 0;
    else die("revocation.on_error must be keep or reject_all");
  }

  lua_getfield(l, ri, "provider");
  if (lua_istable(l, -1)) {
    int pi = lua_gettop(l);
    const char *type = cfg_str(l, pi, "type");
    snprintf(g_revocation.provider_type, sizeof(g_revocation.provider_type),
             "%s", type ? type : "mock");

    const char *sql = cfg_str(l, pi, "sql");
    if (sql) snprintf(g_revocation.sql, sizeof(g_revocation.sql), "%s", sql);
    const char *dsn = cfg_str(l, pi, "dsn");
    if (dsn) snprintf(g_revocation.dsn, sizeof(g_revocation.dsn), "%s", dsn);

    const char *file = cfg_str(l, pi, "file");
    const char *mock_file = cfg_str(l, pi, "mock_file");
    if (file && file[0]) {
      snprintf(g_revocation.source_file, sizeof(g_revocation.source_file), "%s", file);
    } else if (mock_file && mock_file[0]) {
      snprintf(g_revocation.source_file, sizeof(g_revocation.source_file), "%s", mock_file);
    }

    if (g_revocation.enabled) {
      if (strcasecmp(g_revocation.provider_type, "pgsql") == 0) {
        if (!g_revocation.source_file[0]) {
          die("revocation.provider.type=pgsql is not implemented yet; "
              "set provider.mock_file for mock data");
        }
        log_error(LOG_WARN, "revocation: pgsql native provider not built yet, using mock_file %s",
                  g_revocation.source_file);
      } else if (strcasecmp(g_revocation.provider_type, "mock") != 0) {
        die("revocation.provider.type must be mock or pgsql");
      } else if (!g_revocation.source_file[0]) {
        die("revocation.provider.file is required for mock");
      }
    }
    lua_pop(l, 1);
  } else {
    lua_pop(l, 1);
    if (g_revocation.enabled) die("revocation.provider table required");
  }

  lua_pop(l, 1); /* revocation */
}

static int log_level_num(const char *s)
{
  if (!s || !s[0]) return LOG_INFO;
  if (strcasecmp(s, "error") == 0) return LOG_ERROR;
  if (strcasecmp(s, "warn") == 0) return LOG_WARN;
  if (strcasecmp(s, "info") == 0) return LOG_INFO;
  if (strcasecmp(s, "debug") == 0) return LOG_DEBUG;
  die("log.level must be error, warn, info or debug");
  return LOG_INFO;
}

static void parse_log(lua_State *l, int cfg)
{
  lua_getfield(l, cfg, "log");
  if (!lua_istable(l, -1)) { lua_pop(l, 1); return; }
  int li = lua_gettop(l);

  const char *a = cfg_str(l, li, "access");
  if (a) snprintf(g_log_access_path, sizeof(g_log_access_path), "%s", a);
  const char *e = cfg_str(l, li, "error");
  if (e) snprintf(g_log_error_path, sizeof(g_log_error_path), "%s", e);

  const char *lv = cfg_str(l, li, "level");
  if (lv) g_log_level = log_level_num(lv);

  lua_getfield(l, li, "flush_interval");
  if (lua_isnumber(l, -1)) {
    double sec = lua_tonumber(l, -1);
    int ms = (int)(sec * 1000);
    if (ms < 10) ms = 10;
    if (ms > 60000) ms = 60000;
    g_log_flush_ms = ms;
  }
  lua_pop(l, 1);

  long long v;
  if ((v = cfg_ll(l, li, "max_buffer", 4LL * 1024 * 1024)) > 0) {
    g_log_max_bytes = (size_t)v;
  }
  if (g_log_max_bytes < 4096) die("log.max_buffer too small");

  lua_getfield(l, li, "rotate_interval");
  if (lua_isnumber(l, -1)) {
    double sec = lua_tonumber(l, -1);
    int ms = 0;
    if (sec > 0) {
      ms = (int)(sec * 1000);
      if (ms < 100) ms = 100;
      if (ms > 86400000) ms = 86400000;
    }
    g_log_rotate_ms = ms;
  }
  lua_pop(l, 1);

  if ((v = cfg_ll(l, li, "rotate_size", 0)) >= 0) g_log_rotate_size = (size_t)v;
  if ((v = cfg_ll(l, li, "rotate_keep", 7)) >= 0) {
    if (v > 100) v = 100;
    g_log_rotate_keep = (int)v;
  }
  lua_pop(l, 1); /* log */
}

static void parse_server(lua_State *l, int sidx, int cli_port)
{
  int default_port = cli_port > 0 ? cli_port : 8080;

  parse_limits(l, sidx);
  parse_buffers(l, sidx);
  parse_tcp(l, sidx);
  parse_tls(l, sidx);

  lua_getfield(l, sidx, "listen");
  if (lua_isnil(l, -1)) {
    lua_pop(l, 1);
    add_listener("0.0.0.0", default_port, 0);
  } else {
    parse_listen_entry(l, lua_gettop(l), 0, default_port);
    lua_pop(l, 1);
  }
  if (g_listener_count == 0) add_listener("0.0.0.0", default_port, 0);

  int any_tls = 0;
  for (size_t i = 0; i < g_listener_count; i++) {
    if (g_listeners[i].tls) any_tls = 1;
  }
  if (any_tls) {
    if (!g_tls_cert_path[0] || !g_tls_key_path[0])
      die("server.tls.cert and server.tls.key are required for a tls listener");
    g_tls_enabled = 1;
    g_tls_gen = tls_gen_build(1);
    if (!g_tls_gen) die("failed to build TLS configuration");
    tls_gen_ref(g_tls_gen);
  }
}

static void create_listeners(void)
{
  for (size_t i = 0; i < g_listener_count; i++) {
    listener_t *l = &g_listeners[i];
    uv_tcp_init(loop, &l->handle);
    l->handle.data = l;

    unsigned bind_flags = g_tcp.reuse_port ? UV_TCP_REUSEPORT : 0;
    int r;
    if (strchr(l->host, ':')) {
      struct sockaddr_in6 a6;
      r = uv_ip6_addr(l->host, l->port, &a6);
      if (r == 0) r = uv_tcp_bind(&l->handle, (const struct sockaddr *)&a6, bind_flags);
    } else {
      struct sockaddr_in a4;
      r = uv_ip4_addr(l->host, l->port, &a4);
      if (r == 0) r = uv_tcp_bind(&l->handle, (const struct sockaddr *)&a4, bind_flags);
    }
    if (r != 0) die("bind %s:%d failed: %s", l->host, l->port, uv_strerror(r));
    r = uv_listen((uv_stream_t *)&l->handle, g_tcp.backlog, on_connection);
    if (r != 0) die("listen %s:%d failed: %s", l->host, l->port, uv_strerror(r));

    struct sockaddr_storage st;
    int sl = sizeof(st);
    if (uv_tcp_getsockname(&l->handle, (struct sockaddr *)&st, &sl) == 0) {
      if (st.ss_family == AF_INET) {
        l->port = ntohs(((struct sockaddr_in *)&st)->sin_port);
      } else if (st.ss_family == AF_INET6) {
        l->port = ntohs(((struct sockaddr_in6 *)&st)->sin6_port);
      }
    }
  }
}

/* ---------- 初始化 ---------- */

static void init_lua(const char *path, int cli_port)
{
  L = luaL_newstate();
  if (!L) { fprintf(stderr, "cannot create Lua state\n"); exit(1); }
  luaL_openlibs(L);

  lua_getglobal(L, "debug");
  lua_getfield(L, -1, "traceback");
  lua_remove(L, -2);
  traceback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

  if (luaL_dostring(L, STREAM_LIB_LUA) != 0) {
    fprintf(stderr, "failed to load stream lib: %s\n", lua_tostring(L, -1));
    exit(1);
  }
  if (!lua_istable(L, -1)) { fprintf(stderr, "stream lib must return a table\n"); exit(1); }
  stream_lib_ref = luaL_ref(L, LUA_REGISTRYINDEX);

  if (luaL_dofile(L, path) != 0) {
    fprintf(stderr, "failed to load %s: %s\n", path, lua_tostring(L, -1));
    exit(1);
  }
  if (!lua_istable(L, -1)) {
    fprintf(stderr, "%s must return a table\n", path);
    exit(1);
  }
  int cfg = lua_gettop(L);

  /* 业务可读全局 config（uploader URI、路由等） */
  lua_pushvalue(L, cfg);
  lua_setglobal(L, "config");

  parse_revocation(L, cfg);
  parse_log(L, cfg);

  lua_getfield(L, cfg, "server");
  int has_server = lua_istable(L, -1);
  if (has_server) {
    parse_server(L, lua_gettop(L), cli_port);
  } else {
    lua_pop(L, 1);
    add_listener("0.0.0.0", cli_port > 0 ? cli_port : 8080, 0);
  }
  if (has_server) lua_pop(L, 1);

  if (cli_port > 0 && g_listener_count > 0) g_listeners[0].port = cli_port;

  lua_getfield(L, cfg, "app");
  if (lua_isstring(L, -1)) {
    const char *app_path = lua_tostring(L, -1);
    lua_pop(L, 1);
    if (luaL_dofile(L, app_path) != 0) {
      fprintf(stderr, "failed to load app %s: %s\n", app_path, lua_tostring(L, -1));
      exit(1);
    }
    if (!lua_istable(L, -1)) {
      fprintf(stderr, "app %s must return a table\n", app_path);
      exit(1);
    }
    lua_getfield(L, -1, "handle");
    if (!lua_isfunction(L, -1)) {
      fprintf(stderr, "app %s has no handle function\n", app_path);
      exit(1);
    }
    app_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pop(L, 1);
  } else {
    lua_pop(L, 1);
    lua_getfield(L, cfg, "handle");
    if (!lua_isfunction(L, -1)) {
      fprintf(stderr, "%s must define app = \"...\" or a handle function\n", path);
      exit(1);
    }
    app_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  }

  lua_pop(L, 1); /* config table */
}

static void on_sigint(uv_signal_t *h, int signum)
{
  (void)h;
  (void)signum;
  if (g_shutdown_state == 0) begin_graceful_shutdown();
  else force_shutdown();
}

static void on_sighup(uv_signal_t *h, int signum)
{
  (void)h;
  (void)signum;
  log_error(LOG_DEBUG, "SIGHUP ignored; certificate/revocation refresh is periodic");
}

int main(int argc, char **argv)
{
  const char *cfg = argc > 1 ? argv[1] : "config.lua";
  int cli_port = argc > 2 ? atoi(argv[2]) : 0;
  if (cli_port <= 0) {
    const char *pe = getenv("HTTPD_PORT");
    if (pe && *pe) cli_port = atoi(pe);
  }

  size_t env_max_body = 0;
  const char *mb = getenv("HTTPD_MAX_BODY");
  if (mb && *mb) {
    unsigned long long v = strtoull(mb, NULL, 10);
    if (v > 0) env_max_body = (size_t)v;
  }

  signal(SIGPIPE, SIG_IGN);

  init_lua(cfg, cli_port);
  if (env_max_body) max_body_stream = env_max_body;

  loop = uv_default_loop();
  log_init();
  tls_snapshot_init();
  revocation_init();
  create_listeners();

  uv_timer_init(loop, &g_shutdown_timer);

  uv_signal_t sig;
  uv_signal_init(loop, &sig);
  uv_signal_start(&sig, on_sigint, SIGINT);

  uv_signal_t sigterm;
  uv_signal_init(loop, &sigterm);
  uv_signal_start(&sigterm, on_sigint, SIGTERM);

  uv_signal_t sighup;
  uv_signal_init(loop, &sighup);
  uv_signal_start(&sighup, on_sighup, SIGHUP);

  if (g_tls_enabled && g_tls_check_interval_ms > 0) {
    uv_timer_init(loop, &g_tls_check_timer);
    uv_timer_start(&g_tls_check_timer, tls_check_timer_cb,
                   (uint64_t)g_tls_check_interval_ms,
                   (uint64_t)g_tls_check_interval_ms);
  }
  if (g_revocation.enabled && g_revocation.interval_ms > 0) {
    uv_timer_init(loop, &g_revocation_timer);
    uv_timer_start(&g_revocation_timer, revocation_timer_cb,
                   (uint64_t)g_revocation.interval_ms,
                   (uint64_t)g_revocation.interval_ms);
  }

  for (size_t i = 0; i < g_listener_count; i++) {
    listener_t *l = &g_listeners[i];
    log_error(LOG_INFO, "listener %s:%d (%s)",
              l->host, l->port, l->tls ? "https" : "http");
  }
  if (g_tls_enabled) {
    log_error(LOG_INFO, "tls: %zu sni pair(s), periodic check every %dms",
              g_sni_count, g_tls_check_interval_ms);
  }
  if (g_revocation.enabled) {
    log_error(LOG_INFO, "revocation: enabled, %zu entries, periodic every %dms, provider=%s",
              g_revoked ? g_revoked->count : 0, g_revocation.interval_ms,
              g_revocation.provider_type);
  }
  log_error(LOG_INFO,
            "max_body=%zu idle_timeout=%us shutdown_timeout=%ums tcp{nodelay=%d keepalive=%d backlog=%d reuse_port=%d}",
            max_body_stream, g_idle_timeout_ms / 1000, g_shutdown_timeout_ms,
            g_tcp.nodelay, g_tcp.keepalive, g_tcp.backlog, g_tcp.reuse_port);

  uv_run(loop, UV_RUN_DEFAULT);

  log_shutdown();
  lua_close(L);
  return 0;
}
