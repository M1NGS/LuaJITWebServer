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
#include <sys/eventfd.h>
#include <poll.h>
#include <netdb.h>
#include <sys/un.h>
#include <setjmp.h>

#include <uv.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <curl/curl.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>
#include <mbedtls/net_sockets.h>

#include "picohttpparser.h"
#include "httpd_config.h"
#include "config_cdef_bc.h"
#include "httpd_config_bc.h"

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
static __thread size_t g_active_connections = 0;

/* 多 worker（SO_REUSEPORT）进程内线程模型：每 worker 一个 loop + 一个 Lua VM。
 * workers=1 时沿用原有单线程路径；workers>1 时这些资源全部按线程隔离。 */
static size_t g_worker_count = 1;
typedef struct worker_s {
  uv_loop_t loop;
  uv_async_t ctrl;        /* control -> worker（停止/强制停止/reload） */
  uv_thread_t thread;
  int id;
  unsigned reload_seen;
} worker_t;
static worker_t *g_workers;
static uv_mutex_t g_cfg_init_mutex;   /* 串行化 worker 配置写入（只在启动阶段） */
static uv_barrier_t g_init_barrier;
static uv_loop_t g_ctrl_loop;
static uv_async_t g_ctrl_done_async;  /* worker -> control（worker 已退出） */
static volatile int g_ctrl_force;
static volatile int g_ctrl_shutdown;
static volatile int g_ctrl_signal_state;
static unsigned g_ctrl_reload_seq;
static size_t g_workers_done;
static __thread int g_current_worker_id = -1;

typedef struct listener_s {
  uv_tcp_t handle;
  int tls;
  char host[128];
  int port;
} listener_t;

static __thread listener_t *g_listeners;
static __thread size_t g_listener_count;

/* 启动时的 listen 快照（多 worker reload 只允许 listen 不变） */
typedef struct {
  char host[128];
  int port;
  int tls;
} listen_spec_t;
static listen_spec_t *g_listen_specs;
static size_t g_listen_spec_count;

static void listen_snapshot_capture(void)
{
  free(g_listen_specs);
  g_listen_spec_count = g_listener_count;
  g_listen_specs = NULL;
  if (g_listener_count == 0) return;
  g_listen_specs = (listen_spec_t *)calloc(g_listener_count, sizeof(listen_spec_t));
  if (!g_listen_specs) { g_listen_spec_count = 0; return; }
  for (size_t i = 0; i < g_listener_count; i++) {
    snprintf(g_listen_specs[i].host, sizeof(g_listen_specs[i].host), "%s",
             g_listeners[i].host);
    g_listen_specs[i].port = g_listeners[i].port;
    g_listen_specs[i].tls = g_listeners[i].tls;
  }
}

static int listen_snapshot_matches(void)
{
  if (g_listen_spec_count != g_listener_count) return 0;
  for (size_t i = 0; i < g_listen_spec_count; i++) {
    if (strcmp(g_listen_specs[i].host, g_listeners[i].host) != 0 ||
        g_listen_specs[i].port != g_listeners[i].port ||
        g_listen_specs[i].tls != g_listeners[i].tls) return 0;
  }
  return 1;
}

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

static const tcp_opts_t k_tcp_defaults = { 1, 0, 60, 10, 5, 0, 1024, 0, 0, 0 };

static tcp_opts_t g_tcp;

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

static __thread tls_gen_t *g_tls_gen;      /* 当前代（持 1 个引用）；每 worker 独立 */
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
static __thread tls_stamp_t g_tls_stamps[MAX_TLS_PATHS];
static __thread int g_tls_checking;
static int g_tls_check_interval_ms = 10000;
static __thread uv_timer_t g_tls_check_timer;
static __thread char tls_errbuf[1024];

/* ---------- 客户端证书吊销表（自定义数据库 / mock） ---------- */
typedef struct revoked_store_s {
  uint8_t *keys;      /* cap * 32 */
  uint8_t *used;      /* cap */
  size_t cap;
  size_t count;
  _Atomic int refs;   /* 全局发布 + 验证回调临时引用 */
  struct revoked_store_s *next_retire;
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

static const revocation_cfg_t k_revocation_defaults = {
  .enabled = 0,
  .load_on_start = 1,
  .interval_ms = 30000,
  .max_bytes = 64 * 1024 * 1024,
  .max_entries = 500000,
  .reject_all = 0
};
static revocation_cfg_t g_revocation;
static _Atomic(revoked_store_t *) g_revoked;
static uv_mutex_t g_revoke_mu;
static int g_revoke_mu_inited;
static revoked_store_t *g_revoke_retire;
static int g_revocation_checking;
static uv_timer_t g_revocation_timer;
static int g_revocation_inited;

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

/* 配置结构体定义在 src/httpd_config.h（C 与 LuaJIT FFI 共用同一份布局） */
typedef httpd_name_value_t name_value_t;
typedef httpd_log_file_cfg_t log_file_cfg_t;
typedef httpd_log_otlp_cfg_t log_otlp_cfg_t;
typedef httpd_log_syslog_cfg_t log_syslog_cfg_t;

static const httpd_config_t k_config_defaults = {
  .version = 1,
  .log = {
    .level = LOG_INFO,
    .file = {
      .level = -1, .access_on = 1, .error_on = 1,
      .max_bytes = 4 * 1024 * 1024, .flush_ms = 100, .rotate_keep = 7
    },
    .otlp = {
      .level = -1, .access_on = 1, .error_on = 1, .verify = 1,
      .batch_max_records = 2048, .batch_max_bytes = 1024 * 1024,
      .flush_ms = 5000, .queue_max_bytes = 32 * 1024 * 1024,
      .timeout_ms = 5000, .max_retries = 5, .service_name = "luajit-httpd"
    },
    .syslog = {
      .level = -1, .access_on = 1, .error_on = 1, .transport = 0,
      .port = 514, .format = 0, .facility = 16, .tag = "luajit-httpd",
      .queue_max_bytes = 8 * 1024 * 1024, .reconnect_ms = 1000, .verify = 1
    },
  },
};

static httpd_config_t g_config;
/* worker reload 时让 FFI 库写到线程局部副本，避免与 control 发布/其它 worker 争全局 */
static __thread httpd_config_t *t_config;
static char g_config_path[512];
static size_t g_env_max_body;      /* HTTPD_MAX_BODY 覆盖值（reload 时重新应用） */
static int g_cli_port;             /* 命令行端口（旧兼容模式） */

/* 旧名字别名：P1 期间保持现有引用点不变；P2 再统一改为 g_config.log.* */
#define g_log_file    g_config.log.file
#define g_log_otlp    g_config.log.otlp
#define g_log_syslog  g_config.log.syslog
#define g_log_level   g_config.log.level

static void *httpd_config_root(void) { return t_config ? (void *)t_config : (void *)&g_config; }

static int l_httpd_config_root(lua_State *L)
{
  lua_pushinteger(L, (lua_Integer)(uintptr_t)httpd_config_root());
  return 1;
}

/* ABI 自检：Lua 库用 ffi.sizeof/offsetof 与这里逐项对比 */
static int l_httpd_config_abi(lua_State *L)
{
  lua_newtable(L);
  lua_pushinteger(L, (lua_Integer)sizeof(httpd_config_t));
  lua_setfield(L, -2, "config_size");
  lua_pushinteger(L, (lua_Integer)offsetof(httpd_config_t, log));
  lua_setfield(L, -2, "off_log");
  lua_pushinteger(L, (lua_Integer)(offsetof(httpd_config_t, log) +
                                   offsetof(httpd_log_cfg_t, file)));
  lua_setfield(L, -2, "off_log_file");
  lua_pushinteger(L, (lua_Integer)(offsetof(httpd_config_t, log) +
                                   offsetof(httpd_log_cfg_t, otlp)));
  lua_setfield(L, -2, "off_log_otlp");
  lua_pushinteger(L, (lua_Integer)(offsetof(httpd_config_t, log) +
                                   offsetof(httpd_log_cfg_t, syslog)));
  lua_setfield(L, -2, "off_log_syslog");
  return 1;
}

typedef struct {
  const unsigned char *p;
  size_t len;
} bc_reader_t;

/* lua_load 的 reader：第一次返回整段字节码，第二次返回 NULL 表示结束 */
static const char *bc_reader(lua_State *L, void *ud, size_t *size)
{
  bc_reader_t *r = (bc_reader_t *)ud;
  (void)L;
  if (r->len == 0) {
    *size = 0;
    return NULL;
  }
  size_t n = r->len;
  r->len = 0;
  *size = n;
  return (const char *)r->p;
}

/* 执行构建期生成的 LuaJIT 字节码；global_name 非空时把返回值设为全局对象 */
static void inject_bytecode(lua_State *L, const unsigned char *bc, unsigned int len,
                            const char *name, const char *global_name)
{
  bc_reader_t reader = { bc, (size_t)len };
  if (lua_load(L, bc_reader, &reader, name) != 0) {
    fprintf(stderr, "failed to load %s bytecode: %s\n", name, lua_tostring(L, -1));
    exit(1);
  }
  if (lua_pcall(L, 0, 1, 0) != 0) {
    fprintf(stderr, "failed to initialize %s: %s\n", name, lua_tostring(L, -1));
    exit(1);
  }
  if (global_name) lua_setglobal(L, global_name);
  else lua_pop(L, 1);
}

static __thread log_sink_t g_access_log;
static __thread log_sink_t g_error_log;
static __thread int g_log_inited;
static __thread int g_log_shutting_down;

/* ---------- OTLP 发送队列（独立线程 + libcurl） ---------- */

typedef struct otlp_rec_s {
  struct otlp_rec_s *next;
  uint64_t time_ns;
  int is_access;
  int severity_num;
  const char *severity_text;
  char *body;
  size_t body_len;
  /* access 结构化字段 */
  char *method;
  char *path;
  char *remote_addr;
  char *referer;
  char *user_agent;
  int status;
  size_t bytes_sent;
  int minor;
  /* error 字段 */
  const char *level_name;
  int pid;
  unsigned long tid;
  size_t alloc_bytes;
} otlp_rec_t;

typedef struct {
  otlp_rec_t *head;
  otlp_rec_t *tail;
  size_t bytes;
  size_t records;
} otlp_batch_t;

typedef struct {
  uv_mutex_t mu;
  uv_cond_t cond;
  otlp_rec_t *head;
  otlp_rec_t *tail;
  size_t bytes;
  size_t records;
  int stop;
  int flush_req;
  uint64_t last_send_ns;
  uv_thread_t thread;
  int started;
  unsigned long dropped;
  unsigned long sent;
  unsigned long failed;
} otlp_sink_t;

static otlp_sink_t g_otlp;

/* ---------- syslog 发送队列（独立线程 + raw socket） ---------- */

typedef struct syslog_msg_s {
  struct syslog_msg_s *next;
  int severity;
  time_t ts;
  char *msg;
  size_t len;
  size_t alloc_bytes;
} syslog_msg_t;

typedef struct {
  uv_mutex_t mu;
  uv_cond_t cond;
  syslog_msg_t *head;
  syslog_msg_t *tail;
  size_t bytes;
  size_t records;
  int stop;
  int flush_req;
  int reload;                 /* reload 时要求线程重建连接 */
  uv_thread_t thread;
  int started;
  unsigned long dropped;
  unsigned long sent;
  unsigned long failed;
} syslog_sink_t;

static syslog_sink_t g_syslog;

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
  int chunked;               /* Transfer-Encoding: chunked */
  int chunk_state;           /* 0=size,1=data,2=CRLF,3=trailer,4=done */
  size_t chunk_remaining;
  size_t chunk_total;

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

static __thread uv_loop_t *loop;
static __thread lua_State *L;
static __thread int app_ref = LUA_NOREF;
static __thread int traceback_ref = LUA_NOREF;
static __thread int stream_lib_ref = LUA_NOREF;

/* 优雅退出：0=running, 1=draining, 2=forced, 3=done（每 worker 独立） */
static __thread conn_t *g_conns;
static __thread size_t g_conn_count;
static __thread int g_shutdown_state;
static __thread uv_timer_t g_shutdown_timer;
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

/* reload：先把旧 pending 写回旧路径，再切到新路径/参数（enabled 状态不变） */
static void log_sink_update(log_sink_t *s, const char *path, size_t max_bytes,
                            int interval_ms, int rotate_ms, size_t rotate_size,
                            int rotate_keep)
{
  if (!s->enabled) return;
  log_sink_flush_sync(s);
  uv_timer_stop(&s->timer);
  if (s->rotate_interval_ms > 0) uv_timer_stop(&s->rotate_timer);
  snprintf(s->path, sizeof(s->path), "%s", path);
  s->max_bytes = max_bytes;
  s->rotate_size = rotate_size;
  s->rotate_keep = rotate_keep;
  s->rotate_interval_ms = rotate_ms;
  s->bytes_since_rotate = 0;
  uv_timer_start(&s->timer, log_timer_cb, (uint64_t)interval_ms, (uint64_t)interval_ms);
  if (rotate_ms > 0) {
    uv_timer_start(&s->rotate_timer, log_rotate_timer_cb,
                   (uint64_t)rotate_ms, (uint64_t)rotate_ms);
  }
}

/* ==================== 日志三通道：OTLP ==================== */

static uint64_t now_ns_realtime(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ==================== 日志管道（workers>1：per-worker ring + collector） ==================== */

#define LOGP_TARGET_FILE    0x1u
#define LOGP_TARGET_OTLP    0x2u
#define LOGP_TARGET_SYSLOG  0x4u
#define LOG_EVENT_MAX       (16 * 1024)
#define LOG_ACCESS_RING     (1024 * 1024)
#define LOG_ERROR_RING      (64 * 1024)

typedef struct {
  uint32_t total_len;      /* header + payload，8 字节对齐 */
  uint16_t type;           /* 0=pad, 1=access, 2=error */
  uint8_t level;
  uint8_t targets;         /* LOGP_TARGET_* 位图 */
  uint32_t status;
  uint32_t minor;
  uint64_t body_bytes;
  uint64_t ts_ns;
  int32_t pid;
  uint32_t tid;
  uint16_t method_len, path_len, client_len, ref_len, ua_len, line_len;
} log_event_t;

typedef struct {
  uint32_t total_len;
  uint16_t type;
  uint16_t pad2;
} log_pad_t;

typedef struct {
  _Atomic uint32_t head;   /* 生产者 release */
  _Atomic uint32_t tail;   /* 消费者 release */
  uint32_t cap, mask;
  unsigned notify_count;
  unsigned long dropped;
  char *data;
} log_ring_t;

typedef struct {
  log_ring_t access;
  log_ring_t error;
} worker_log_rings_t;

static worker_log_rings_t *g_worker_rings;
static size_t g_worker_ring_count;
static int g_log_pipeline;
static int g_log_eventfd = -1;
static _Atomic int g_log_stop;
static uv_thread_t g_log_collector_thread;
static int g_log_pipeline_started;
static size_t g_log_init_done;

static void otlp_enqueue_event(const log_event_t *ev);
static int otlp_start(void);
static void otlp_shutdown(void);
static int syslog_start(void);
static void syslog_shutdown(void);
static int syslog_sev(int level);
static void syslog_enqueue(int severity, const char *msg, size_t len);

static inline const char *log_ev_payload(const log_event_t *e)
{
  return (const char *)(e + 1);
}

static inline const char *log_ev_line(const log_event_t *e)
{
  const char *p = log_ev_payload(e);
  p += e->method_len + e->path_len + e->client_len + e->ref_len + e->ua_len;
  return p;
}

static int log_ring_init(log_ring_t *r, size_t cap)
{
  memset(r, 0, sizeof(*r));
  r->cap = (uint32_t)cap;
  r->mask = r->cap - 1;
  r->data = (char *)malloc(cap);
  return r->data ? 0 : -1;
}

static void log_ring_free(log_ring_t *r)
{
  free(r->data);
  r->data = NULL;
}

/* 单生产者：写 payload 后 release 提交 head；consumer 只读 head 之前的条目 */
static int log_ring_write(log_ring_t *r, const log_event_t *ev)
{
  if (!r || !r->data) return -1;
  uint32_t len = ev->total_len;
  uint32_t head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
  uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
  uint32_t off = head & r->mask;
  uint32_t pad = 0;
  if (off + len > r->cap) pad = r->cap - off;
  if (r->cap - (head - tail) < pad + len) {
    r->dropped++;
    return -1;
  }
  if (pad) {
    log_pad_t *p = (log_pad_t *)(r->data + off);
    p->total_len = pad;
    p->type = 0;
    head += pad;
    off = 0;
  }
  memcpy(r->data + off, ev, len);
  __atomic_store_n(&r->head, head + len, __ATOMIC_RELEASE);

  if (++r->notify_count >= 256) {
    r->notify_count = 0;
    if (g_log_eventfd >= 0) {
      uint64_t one = 1;
      (void)write(g_log_eventfd, &one, sizeof(one));
    }
  }
  return 0;
}

static log_ring_t *log_ring_for(int error)
{
  if (!g_log_pipeline || g_current_worker_id < 0 ||
      (size_t)g_current_worker_id >= g_worker_ring_count || !g_worker_rings) {
    return NULL;
  }
  return error ? &g_worker_rings[g_current_worker_id].error
               : &g_worker_rings[g_current_worker_id].access;
}

static int log_event_emit(log_ring_t *r, uint16_t type, uint8_t level, uint8_t targets,
                          int status, size_t bytes, int minor, int32_t pid, uint32_t tid,
                          const char *method, size_t ml, const char *path, size_t pl,
                          const char *client, size_t cl, const char *ref, size_t rl,
                          const char *ua, size_t ul, const char *line, size_t ll)
{
  if (!r) return -1;
  if (ml > 16) ml = 16;
  if (pl > 4096) pl = 4096;
  if (cl > 64) cl = 64;
  if (rl > 1024) rl = 1024;
  if (ul > 1024) ul = 1024;
  if (ll > 8192) ll = 8192;

  size_t total = sizeof(log_event_t) + ml + pl + cl + rl + ul + ll;
  total = (total + 7) & ~(size_t)7;
  if (total > LOG_EVENT_MAX) return -1;

  char buf[LOG_EVENT_MAX];
  log_event_t *e = (log_event_t *)buf;
  memset(e, 0, sizeof(*e));
  e->total_len = (uint32_t)total;
  e->type = type;
  e->level = level;
  e->targets = targets;
  e->status = (uint32_t)(status > 0 ? status : 0);
  e->minor = (uint32_t)minor;
  e->body_bytes = bytes;
  e->ts_ns = now_ns_realtime();
  e->pid = pid;
  e->tid = tid;
  e->method_len = (uint16_t)ml;
  e->path_len = (uint16_t)pl;
  e->client_len = (uint16_t)cl;
  e->ref_len = (uint16_t)rl;
  e->ua_len = (uint16_t)ul;
  e->line_len = (uint16_t)ll;

  char *p = buf + sizeof(log_event_t);
  if (ml) { memcpy(p, method, ml); p += ml; }
  if (pl) { memcpy(p, path, pl); p += pl; }
  if (cl) { memcpy(p, client, cl); p += cl; }
  if (rl) { memcpy(p, ref, rl); p += rl; }
  if (ul) { memcpy(p, ua, ul); p += ul; }
  if (ll) { memcpy(p, line, ll); p += ll; }
  memset(p, 0, total - (size_t)(p - buf));
  return log_ring_write(r, e);
}

/* ---- file writer：唯一写者，负责写盘和 rotate ---- */

typedef struct log_file_msg_s {
  struct log_file_msg_s *next;
  uint16_t type;
  size_t len;
  char data[];
} log_file_msg_t;

typedef struct {
  uv_mutex_t mu;
  uv_cond_t cond;
  log_file_msg_t *head, *tail;
  size_t bytes, max_bytes;
  int stop, started;
  int reload;              /* control 请求切换路径/参数 */
  uv_thread_t thread;
  unsigned long dropped;
  char access_path[512], error_path[512];
  int access_on, error_on;
  int rotate_keep, rotate_ms;
  size_t rotate_size;
  uint64_t last_rotate_ns;
  size_t bytes_since[2];
} log_file_writer_t;

static log_file_writer_t g_file_writer;

typedef struct {
  char *p;
  size_t len, cap;
} log_lbuf_t;

static int log_lbuf_add(log_lbuf_t *b, const char *s, size_t n)
{
  if (b->len + n > b->cap) {
    size_t nc = b->cap ? b->cap : 4096;
    while (nc < b->len + n) nc <<= 1;
    char *np = (char *)realloc(b->p, nc);
    if (!np) return -1;
    b->p = np;
    b->cap = nc;
  }
  memcpy(b->p + b->len, s, n);
  b->len += n;
  return 0;
}

static const char *log_file_path(int idx)
{
  return idx ? g_file_writer.error_path : g_file_writer.access_path;
}

static void log_file_rotate(int idx)
{
  const char *path = log_file_path(idx);
  if (!path[0]) return;
  if (g_file_writer.rotate_keep <= 0) {
    if (truncate(path, 0) != 0)
      fprintf(stderr, "log: truncate %s: %s\n", path, strerror(errno));
  } else {
    char from[1024], to[1024];
    for (int i = g_file_writer.rotate_keep - 1; i >= 1; i--) {
      snprintf(from, sizeof(from), "%s.%d", path, i);
      snprintf(to, sizeof(to), "%s.%d", path, i + 1);
      if (rename(from, to) != 0 && errno != ENOENT)
        fprintf(stderr, "log: rename %s: %s\n", from, strerror(errno));
    }
    snprintf(to, sizeof(to), "%s.1", path);
    if (rename(path, to) != 0 && errno != ENOENT)
      fprintf(stderr, "log: rename %s: %s\n", path, strerror(errno));
  }
  g_file_writer.bytes_since[idx] = 0;
}

static void log_file_write(int idx, const char *data, size_t len)
{
  const char *path = log_file_path(idx);
  if (!path[0] || len == 0) return;
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) {
    fprintf(stderr, "log: open %s: %s\n", path, strerror(errno));
    g_file_writer.dropped++;
    return;
  }
  size_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, data + off, len - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      fprintf(stderr, "log: write %s: %s\n", path, strerror(errno));
      g_file_writer.dropped++;
      break;
    }
    off += (size_t)n;
  }
  close(fd);
  if (off == len) g_file_writer.bytes_since[idx] += len;
}

static void log_file_flush_buf(int idx, log_lbuf_t *b)
{
  if (!b->len) return;
  if (g_file_writer.rotate_size &&
      g_file_writer.bytes_since[idx] + b->len > g_file_writer.rotate_size) {
    log_file_rotate(idx);
  }
  log_file_write(idx, b->p, b->len);
  b->len = 0;
  /* 单批本身超过 rotate_size 时，写完立即切，保证下一批落到新文件 */
  if (g_file_writer.rotate_size &&
      g_file_writer.bytes_since[idx] >= g_file_writer.rotate_size) {
    log_file_rotate(idx);
  }
}

static void log_file_time_rotate(void)
{
  if (g_file_writer.rotate_ms <= 0) return;
  uint64_t now = uv_hrtime();
  if (now - g_file_writer.last_rotate_ns <
      (uint64_t)g_file_writer.rotate_ms * 1000000ULL) return;
  log_file_rotate(0);
  log_file_rotate(1);
  g_file_writer.last_rotate_ns = now;
}

static void log_file_enqueue(uint16_t type, const char *line, size_t len)
{
  int idx = (type == 2) ? 1 : 0;
  if (!g_file_writer.started) return;
  if ((idx == 0 && !g_file_writer.access_on) ||
      (idx == 1 && !g_file_writer.error_on)) return;
  if (len == 0) return;

  log_file_msg_t *m = (log_file_msg_t *)malloc(sizeof(*m) + len);
  if (!m) { g_file_writer.dropped++; return; }
  m->next = NULL;
  m->type = type;
  m->len = len;
  memcpy(m->data, line, len);

  uv_mutex_lock(&g_file_writer.mu);
  if (g_file_writer.bytes + len > g_file_writer.max_bytes) {
    g_file_writer.dropped++;
    uv_mutex_unlock(&g_file_writer.mu);
    free(m);
    return;
  }
  if (g_file_writer.tail) g_file_writer.tail->next = m;
  else g_file_writer.head = m;
  g_file_writer.tail = m;
  g_file_writer.bytes += len;
  uv_cond_signal(&g_file_writer.cond);
  uv_mutex_unlock(&g_file_writer.mu);
}

static void log_file_apply_config(void)
{
  snprintf(g_file_writer.access_path, sizeof(g_file_writer.access_path), "%s",
           g_log_file.access_path);
  snprintf(g_file_writer.error_path, sizeof(g_file_writer.error_path), "%s",
           g_log_file.error_path);
  g_file_writer.access_on = g_log_file.access_on && g_file_writer.access_path[0];
  g_file_writer.error_on = g_log_file.error_on && g_file_writer.error_path[0];
  g_file_writer.max_bytes = g_log_file.max_bytes ? g_log_file.max_bytes : 4 * 1024 * 1024;
  g_file_writer.rotate_keep = g_log_file.rotate_keep;
  g_file_writer.rotate_ms = g_log_file.rotate_ms;
  g_file_writer.rotate_size = g_log_file.rotate_size;
  g_file_writer.last_rotate_ns = uv_hrtime();
  g_file_writer.bytes_since[0] = g_file_writer.bytes_since[1] = 0;
}

static void log_file_writer_main(void *arg)
{
  (void)arg;
  g_current_worker_id = -1;
  log_lbuf_t bufs[2] = { {0}, {0} };

  for (;;) {
    uv_mutex_lock(&g_file_writer.mu);
    while (!g_file_writer.head && !g_file_writer.stop && !g_file_writer.reload) {
      /* 100ms 到点也跳出等待，让空闲缓冲落盘（rotate 也按这个节奏检查） */
      uv_cond_timedwait(&g_file_writer.cond, &g_file_writer.mu, 100ULL * 1000000ULL);
      if (!g_file_writer.head && !g_file_writer.reload) break;
    }
    log_file_msg_t *list = g_file_writer.head;
    g_file_writer.head = g_file_writer.tail = NULL;
    g_file_writer.bytes = 0;
    int stop = g_file_writer.stop;
    int reload = g_file_writer.reload;
    if (reload) g_file_writer.reload = 0;
    uv_mutex_unlock(&g_file_writer.mu);

    log_file_msg_t *m = list;
    while (m) {
      log_file_msg_t *next = m->next;
      int idx = (m->type == 2) ? 1 : 0;
      if (log_lbuf_add(&bufs[idx], m->data, m->len) != 0)
        g_file_writer.dropped++;
      free(m);
      m = next;
    }

    for (int i = 0; i < 2; i++) {
      if (bufs[i].len >= 64 * 1024) log_file_flush_buf(i, &bufs[i]);
    }
    if (!list || reload) {
      for (int i = 0; i < 2; i++) log_file_flush_buf(i, &bufs[i]);
      log_file_time_rotate();
    }
    if (reload) log_file_apply_config();  /* 旧数据已写回旧路径，再切新配置 */
    if (stop) break;
  }

  for (int i = 0; i < 2; i++) {
    log_file_flush_buf(i, &bufs[i]);
    free(bufs[i].p);
  }
}

static int log_file_writer_start(void)
{
  memset(&g_file_writer, 0, sizeof(g_file_writer));
  if (!g_log_file.enabled) return 0;
  log_file_apply_config();
  if (uv_mutex_init(&g_file_writer.mu) != 0) return -1;
  if (uv_cond_init(&g_file_writer.cond) != 0) {
    uv_mutex_destroy(&g_file_writer.mu);
    return -1;
  }
  g_file_writer.started = 1;
  if (uv_thread_create(&g_file_writer.thread, log_file_writer_main, NULL) != 0) {
    g_file_writer.started = 0;
    uv_cond_destroy(&g_file_writer.cond);
    uv_mutex_destroy(&g_file_writer.mu);
    return -1;
  }
  return 0;
}

static void log_file_writer_reconfigure(void)
{
  if (!g_file_writer.started) return;
  uv_mutex_lock(&g_file_writer.mu);
  g_file_writer.reload = 1;
  uv_cond_signal(&g_file_writer.cond);
  uv_mutex_unlock(&g_file_writer.mu);
}

static void log_file_writer_stop(void)
{
  if (!g_file_writer.started) return;
  uv_mutex_lock(&g_file_writer.mu);
  g_file_writer.stop = 1;
  uv_cond_signal(&g_file_writer.cond);
  uv_mutex_unlock(&g_file_writer.mu);
  uv_thread_join(&g_file_writer.thread);
  uv_cond_destroy(&g_file_writer.cond);
  uv_mutex_destroy(&g_file_writer.mu);
  g_file_writer.started = 0;
}

/* ---- collector：drain 所有 worker ring 并按 targets 位图分发 ---- */

static void log_event_dispatch(const log_event_t *ev)
{
  const char *line = log_ev_line(ev);
  size_t ll = ev->line_len;
  if (ev->targets & LOGP_TARGET_FILE) log_file_enqueue(ev->type, line, ll);
  if (ev->targets & LOGP_TARGET_OTLP) otlp_enqueue_event(ev);
  if (ev->targets & LOGP_TARGET_SYSLOG) {
    int sev = (ev->type == 1) ? 6 : syslog_sev(ev->level);
    syslog_enqueue(sev, line, ll);
  }
}

static int log_ring_drain(log_ring_t *r, char *buf)
{
  if (!r || !r->data) return 0;
  uint32_t head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
  uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
  int processed = 0;

  while (tail != head) {
    uint32_t off = tail & r->mask;
    const log_event_t *e = (const log_event_t *)(r->data + off);
    uint32_t len = e->total_len;
    if (len < sizeof(log_pad_t) || len > r->cap || tail + len > head) break;
    if (e->type == 0) {                 /* wrap pad */
      tail += len;
      __atomic_store_n(&r->tail, tail, __ATOMIC_RELEASE);
      continue;
    }
    if (len > LOG_EVENT_MAX) {          /* 防御：损坏条目直接跳过 */
      tail += len;
      __atomic_store_n(&r->tail, tail, __ATOMIC_RELEASE);
      continue;
    }
    memcpy(buf, e, len);
    tail += len;
    __atomic_store_n(&r->tail, tail, __ATOMIC_RELEASE);
    log_event_dispatch((const log_event_t *)buf);
    processed++;
  }
  return processed;
}

static void log_collector_main(void *arg)
{
  (void)arg;
  g_current_worker_id = -1;
  char *buf = (char *)malloc(LOG_EVENT_MAX);
  if (!buf) return;

  for (;;) {
    struct pollfd pfd;
    pfd.fd = g_log_eventfd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int pr = poll(&pfd, 1, 100);
    if (pr > 0 && (pfd.revents & POLLIN)) {
      uint64_t v;
      while (read(g_log_eventfd, &v, sizeof(v)) > 0) { }
    }

    int progress = 0;
    for (size_t i = 0; i < g_worker_ring_count; i++) {
      progress += log_ring_drain(&g_worker_rings[i].access, buf);
      progress += log_ring_drain(&g_worker_rings[i].error, buf);
    }
    if (__atomic_load_n(&g_log_stop, __ATOMIC_ACQUIRE) && progress == 0) break;
  }
  free(buf);
}

static int log_rings_alloc(size_t n)
{
  g_worker_rings = (worker_log_rings_t *)calloc(n, sizeof(worker_log_rings_t));
  if (!g_worker_rings) return -1;
  g_worker_ring_count = n;
  for (size_t i = 0; i < n; i++) {
    if (log_ring_init(&g_worker_rings[i].access, LOG_ACCESS_RING) != 0 ||
        log_ring_init(&g_worker_rings[i].error, LOG_ERROR_RING) != 0) {
      return -1;
    }
  }
  return 0;
}

static void log_rings_free(void)
{
  if (!g_worker_rings) return;
  for (size_t i = 0; i < g_worker_ring_count; i++) {
    log_ring_free(&g_worker_rings[i].access);
    log_ring_free(&g_worker_rings[i].error);
  }
  free(g_worker_rings);
  g_worker_rings = NULL;
  g_worker_ring_count = 0;
}

static void log_pipeline_start(void)
{
  if (g_log_pipeline_started) return;
  g_log_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (g_log_eventfd < 0) {
    fprintf(stderr, "log: eventfd: %s\n", strerror(errno));
    return;
  }
  __atomic_store_n(&g_log_stop, 0, __ATOMIC_RELEASE);

  if (log_file_writer_start() != 0)
    fprintf(stderr, "log: file writer start failed\n");

  if (uv_thread_create(&g_log_collector_thread, log_collector_main, NULL) != 0) {
    fprintf(stderr, "log: collector thread create failed\n");
    close(g_log_eventfd);
    g_log_eventfd = -1;
    return;
  }

  if (g_log_otlp.enabled && otlp_start() != 0) g_log_otlp.enabled = 0;
  if (g_log_syslog.enabled && syslog_start() != 0) g_log_syslog.enabled = 0;
  g_log_pipeline_started = 1;
}

static void log_pipeline_stop(void)
{
  if (!g_log_pipeline_started) return;
  __atomic_store_n(&g_log_stop, 1, __ATOMIC_RELEASE);
  if (g_log_eventfd >= 0) {
    uint64_t one = 1;
    (void)write(g_log_eventfd, &one, sizeof(one));
  }
  uv_thread_join(&g_log_collector_thread);
  log_file_writer_stop();
  otlp_shutdown();
  syslog_shutdown();
  if (g_log_eventfd >= 0) {
    close(g_log_eventfd);
    g_log_eventfd = -1;
  }
  g_log_pipeline_started = 0;
}

static char *log_strndup(const char *s, size_t n)
{
  if (!s) return NULL;
  char *p = (char *)malloc(n + 1);
  if (!p) return NULL;
  memcpy(p, s, n);
  p[n] = 0;
  return p;
}

/* ---- 极简 protobuf 写入器（只覆盖 OTLP ExportLogsServiceRequest 的 wire type） ---- */
typedef struct {
  uint8_t *p;
  size_t len;
  size_t cap;
  int err;
} pbuf_t;

static void pbuf_put(pbuf_t *b, const void *data, size_t n)
{
  if (b->err) return;
  if (b->len + n > b->cap) {
    size_t nc = b->cap ? b->cap : 256;
    while (nc < b->len + n) nc <<= 1;
    uint8_t *np = (uint8_t *)realloc(b->p, nc);
    if (!np) { b->err = 1; return; }
    b->p = np;
    b->cap = nc;
  }
  memcpy(b->p + b->len, data, n);
  b->len += n;
}

static void pbuf_varint(pbuf_t *b, uint64_t v)
{
  uint8_t tmp[10];
  int i = 0;
  while (v >= 0x80) {
    tmp[i++] = (uint8_t)(v & 0x7f) | 0x80;
    v >>= 7;
  }
  tmp[i++] = (uint8_t)v;
  pbuf_put(b, tmp, (size_t)i);
}

static void pb_tag(pbuf_t *b, int field, int wire)
{
  pbuf_varint(b, ((uint64_t)field << 3) | (uint64_t)wire);
}

static void pb_len_field(pbuf_t *b, int field, size_t len)
{
  pb_tag(b, field, 2);
  pbuf_varint(b, (uint64_t)len);
}

static void pb_fixed64(pbuf_t *b, int field, uint64_t v)
{
  pb_tag(b, field, 1);
  uint8_t tmp[8];
  for (int i = 0; i < 8; i++) tmp[i] = (uint8_t)(v >> (8 * i));
  pbuf_put(b, tmp, 8);
}

static void pb_varint_field(pbuf_t *b, int field, uint64_t v)
{
  pb_tag(b, field, 0);
  pbuf_varint(b, v);
}

static void pb_string_n(pbuf_t *b, int field, const char *s, size_t n)
{
  pb_len_field(b, field, n);
  pbuf_put(b, s, n);
}

static void pb_string(pbuf_t *b, int field, const char *s)
{
  pb_string_n(b, field, s, strlen(s));
}

static void pb_nested(pbuf_t *b, int field, const pbuf_t *child)
{
  pb_len_field(b, field, child->len);
  pbuf_put(b, child->p, child->len);
}

/* KeyValue { key(1)=string, value(2)=AnyValue{string_value(1)} } */
static void pb_kv_string(pbuf_t *b, int field, const char *key, const char *value, size_t value_len)
{
  pbuf_t kv = { 0 }, av = { 0 };
  pb_string(&kv, 1, key);
  pb_string_n(&av, 1, value, value_len);
  pb_nested(&kv, 2, &av);
  free(av.p);
  pb_nested(b, field, &kv);
  free(kv.p);
}

/* AnyValue{int_value(3)}；负数按 protobuf int64 的 10 字节 varint 编码 */
static void pb_kv_int(pbuf_t *b, int field, const char *key, int64_t value)
{
  pbuf_t kv = { 0 }, av = { 0 };
  pb_string(&kv, 1, key);
  pb_varint_field(&av, 3, (uint64_t)value);
  pb_nested(&kv, 2, &av);
  free(av.p);
  pb_nested(b, field, &kv);
  free(kv.p);
}

static int otlp_sev_num(int level)
{
  switch (level) {
    case LOG_ERROR: return 17;  /* ERROR */
    case LOG_WARN:  return 13;  /* WARN */
    case LOG_INFO:  return 9;   /* INFO */
    default:        return 5;   /* DEBUG */
  }
}

static const char *otlp_sev_text(int level)
{
  switch (level) {
    case LOG_ERROR: return "ERROR";
    case LOG_WARN:  return "WARN";
    case LOG_INFO:  return "INFO";
    default:        return "DEBUG";
  }
}

static const char *log_level_name(int level)
{
  switch (level) {
    case LOG_ERROR: return "error";
    case LOG_WARN:  return "warn";
    case LOG_INFO:  return "info";
    default:        return "debug";
  }
}

/* 一条 LogRecord 编码为 protobuf（字段号见 OTel logs.proto） */
static pbuf_t otlp_encode_record(const otlp_rec_t *r)
{
  pbuf_t rec = { 0 }, body = { 0 };

  pb_fixed64(&rec, 1, r->time_ns);                       /* time_unix_nano */
  pb_varint_field(&rec, 2, (uint64_t)r->severity_num);   /* severity_number */
  pb_string(&rec, 3, r->severity_text);                  /* severity_text */

  pb_string_n(&body, 1, r->body, r->body_len);           /* AnyValue.string_value */
  pb_nested(&rec, 5, &body);                             /* body */
  free(body.p);

  if (r->is_access) {
    pb_kv_string(&rec, 6, "log.source", "access", 6);
    if (r->method) pb_kv_string(&rec, 6, "http.request.method", r->method, strlen(r->method));
    if (r->path) pb_kv_string(&rec, 6, "url.path", r->path, strlen(r->path));
    pb_kv_int(&rec, 6, "http.response.status_code", r->status);
    pb_kv_int(&rec, 6, "body_bytes_sent", (int64_t)r->bytes_sent);
    if (r->remote_addr) pb_kv_string(&rec, 6, "client.address", r->remote_addr, strlen(r->remote_addr));
    if (r->referer) pb_kv_string(&rec, 6, "http.request.referrer", r->referer, strlen(r->referer));
    if (r->user_agent) pb_kv_string(&rec, 6, "http.user_agent", r->user_agent, strlen(r->user_agent));
  } else {
    pb_kv_string(&rec, 6, "log.source", "error", 5);
    pb_kv_string(&rec, 6, "log.level", r->level_name, strlen(r->level_name));
    pb_kv_int(&rec, 6, "process.pid", r->pid);
    pb_kv_int(&rec, 6, "thread.id", (int64_t)r->tid);
  }
  return rec;
}

/* ExportLogsServiceRequest：access/error 各一个 ScopeLogs，共用同一个 Resource */
static int otlp_encode_request(const otlp_batch_t *b, uint8_t **out, size_t *out_len)
{
  pbuf_t access = { 0 }, error = { 0 };

  for (otlp_rec_t *r = b->head; r; r = r->next) {
    pbuf_t rec = otlp_encode_record(r);
    if (rec.err) {
      free(rec.p);
      free(access.p);
      free(error.p);
      return -1;
    }
    pbuf_t *scope = r->is_access ? &access : &error;
    pb_nested(scope, 2, &rec);   /* ScopeLogs.log_records */
    free(rec.p);
  }
  if (access.err || error.err) {
    free(access.p);
    free(error.p);
    return -1;
  }
  if (access.len == 0 && error.len == 0) {
    free(access.p);
    free(error.p);
    return 0;
  }

  pbuf_t *scopes[2] = { &access, &error };
  const char *snames[2] = { "httpd.access", "httpd.error" };
  for (int i = 0; i < 2; i++) {
    if (scopes[i]->len == 0) continue;
    pbuf_t is = { 0 };
    pb_string(&is, 1, snames[i]);
    pb_string(&is, 2, "1");
    pb_nested(scopes[i], 1, &is);   /* ScopeLogs.scope；字段顺序不影响解析 */
    free(is.p);
  }

  pbuf_t res = { 0 };
  pb_kv_string(&res, 1, "service.name", g_log_otlp.service_name,
               strlen(g_log_otlp.service_name));
  char hostname[128] = { 0 };
  gethostname(hostname, sizeof(hostname) - 1);
  if (hostname[0]) pb_kv_string(&res, 1, "host.name", hostname, strlen(hostname));
  for (int i = 0; i < g_log_otlp.nresource; i++) {
    pb_kv_string(&res, 1, g_log_otlp.resource[i].name, g_log_otlp.resource[i].value,
                 strlen(g_log_otlp.resource[i].value));
  }

  pbuf_t rl = { 0 };
  pb_nested(&rl, 1, &res);          /* ResourceLogs.resource */
  free(res.p);
  if (access.len) pb_nested(&rl, 2, &access);
  if (error.len) pb_nested(&rl, 2, &error);
  free(access.p);
  free(error.p);

  pbuf_t req = { 0 };
  pb_nested(&req, 1, &rl);         /* ExportLogsServiceRequest.resource_logs */
  free(rl.p);

  if (req.err) {
    free(req.p);
    return -1;
  }
  *out = req.p;
  *out_len = req.len;
  return 0;
}

static size_t otlp_rec_bytes(const otlp_rec_t *r)
{
  return sizeof(*r) + r->body_len
    + (r->method ? strlen(r->method) : 0)
    + (r->path ? strlen(r->path) : 0)
    + (r->remote_addr ? strlen(r->remote_addr) : 0)
    + (r->referer ? strlen(r->referer) : 0)
    + (r->user_agent ? strlen(r->user_agent) : 0);
}

static void otlp_rec_free(otlp_rec_t *r)
{
  if (!r) return;
  free(r->body);
  free(r->method);
  free(r->path);
  free(r->remote_addr);
  free(r->referer);
  free(r->user_agent);
  free(r);
}

static void otlp_batch_free(otlp_batch_t *b)
{
  otlp_rec_t *r = b->head;
  while (r) {
    otlp_rec_t *next = r->next;
    otlp_rec_free(r);
    r = next;
  }
  memset(b, 0, sizeof(*b));
}

/* 入队：队列超限丢最旧；达到批量阈值时唤醒发送线程 */
static void otlp_rec_push(otlp_rec_t *rec)
{
  if (!rec) return;
  size_t sz = rec->alloc_bytes;
  int sig = 0;

  uv_mutex_lock(&g_otlp.mu);
  int was_empty = g_otlp.head == NULL;
  if (sz > g_log_otlp.queue_max_bytes) {
    g_otlp.dropped++;
    uv_mutex_unlock(&g_otlp.mu);
    otlp_rec_free(rec);
    return;
  }
  while (g_otlp.bytes + sz > g_log_otlp.queue_max_bytes && g_otlp.head) {
    otlp_rec_t *old = g_otlp.head;
    g_otlp.head = old->next;
    if (!g_otlp.head) g_otlp.tail = NULL;
    g_otlp.bytes -= old->alloc_bytes;
    if (g_otlp.records) g_otlp.records--;
    g_otlp.dropped++;
    otlp_rec_free(old);
  }
  if (g_otlp.tail) g_otlp.tail->next = rec;
  else g_otlp.head = rec;
  g_otlp.tail = rec;
  rec->next = NULL;
  g_otlp.bytes += sz;
  g_otlp.records++;
  if (was_empty ||
      g_otlp.bytes >= g_log_otlp.batch_max_bytes ||
      g_otlp.records >= (size_t)g_log_otlp.batch_max_records) {
    sig = 1;
  }
  uv_mutex_unlock(&g_otlp.mu);
  if (sig) uv_cond_signal(&g_otlp.cond);
}

static void otlp_enqueue_access(const request_t *r, const char *remote_addr,
                                int status, size_t written,
                                const char *ref, size_t ref_len,
                                const char *ua, size_t ua_len,
                                const char *line, size_t line_len)
{
  if (!g_log_otlp.enabled || !g_log_otlp.access_on || g_log_shutting_down) return;
  while (line_len && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r')) line_len--;

  otlp_rec_t *rec = (otlp_rec_t *)calloc(1, sizeof(*rec));
  if (!rec) { g_otlp.dropped++; return; }
  rec->is_access = 1;
  rec->time_ns = now_ns_realtime();
  rec->severity_num = 9;
  rec->severity_text = "INFO";
  rec->status = status;
  rec->bytes_sent = written;
  rec->body_len = line_len;
  rec->body = log_strndup(line, line_len);
  if (r->method) rec->method = log_strndup(r->method, r->method_len);
  if (r->path) rec->path = log_strndup(r->path, r->path_len);
  else if (r->target) rec->path = log_strndup(r->target, r->target_len);
  if (remote_addr) rec->remote_addr = log_strndup(remote_addr, strlen(remote_addr));
  if (ref) rec->referer = log_strndup(ref, ref_len);
  if (ua) rec->user_agent = log_strndup(ua, ua_len);
  if (!rec->body) { otlp_rec_free(rec); g_otlp.dropped++; return; }
  rec->alloc_bytes = otlp_rec_bytes(rec);
  otlp_rec_push(rec);
}

static void otlp_enqueue_error(int level, const char *msg, size_t msg_len)
{
  if (!g_log_otlp.enabled || !g_log_otlp.error_on || g_log_shutting_down) return;
  while (msg_len && (msg[msg_len - 1] == '\n' || msg[msg_len - 1] == '\r')) msg_len--;

  otlp_rec_t *rec = (otlp_rec_t *)calloc(1, sizeof(*rec));
  if (!rec) { g_otlp.dropped++; return; }
  rec->is_access = 0;
  rec->time_ns = now_ns_realtime();
  rec->severity_num = otlp_sev_num(level);
  rec->severity_text = otlp_sev_text(level);
  rec->level_name = log_level_name(level);
  rec->pid = (int)getpid();
  rec->tid = (unsigned long)uv_thread_self();
  rec->body_len = msg_len;
  rec->body = log_strndup(msg, msg_len);
  if (!rec->body) { otlp_rec_free(rec); g_otlp.dropped++; return; }
  rec->alloc_bytes = otlp_rec_bytes(rec);
  otlp_rec_push(rec);
}

/* collector -> OTLP：从 ring 事件重建记录，不再依赖 request_t 指针 */
static void otlp_enqueue_event(const log_event_t *ev)
{
  if (!g_log_otlp.enabled) return;
  if (ev->type == 1) {
    if (!g_log_otlp.access_on) return;
  } else {
    if (!g_log_otlp.error_on) return;
  }

  const char *line = log_ev_line(ev);
  size_t line_len = ev->line_len;
  while (line_len && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r')) line_len--;

  const char *p = log_ev_payload(ev);
  const char *method = p; p += ev->method_len;
  const char *path = p; p += ev->path_len;
  const char *client = p; p += ev->client_len;
  const char *ref = p; p += ev->ref_len;
  const char *ua = p;

  otlp_rec_t *rec = (otlp_rec_t *)calloc(1, sizeof(*rec));
  if (!rec) { g_otlp.dropped++; return; }

  rec->time_ns = ev->ts_ns;
  rec->body_len = line_len;
  rec->body = log_strndup(line, line_len);
  if (!rec->body) { otlp_rec_free(rec); g_otlp.dropped++; return; }

  if (ev->type == 1) {
    rec->is_access = 1;
    rec->severity_num = 9;
    rec->severity_text = "INFO";
    rec->status = (int)ev->status;
    rec->bytes_sent = (size_t)ev->body_bytes;
    rec->minor = (int)ev->minor;
    if (ev->method_len) rec->method = log_strndup(method, ev->method_len);
    if (ev->path_len) rec->path = log_strndup(path, ev->path_len);
    if (ev->client_len) rec->remote_addr = log_strndup(client, ev->client_len);
    if (ev->ref_len) rec->referer = log_strndup(ref, ev->ref_len);
    if (ev->ua_len) rec->user_agent = log_strndup(ua, ev->ua_len);
  } else {
    rec->is_access = 0;
    rec->severity_num = otlp_sev_num(ev->level);
    rec->severity_text = otlp_sev_text(ev->level);
    rec->level_name = log_level_name(ev->level);
    rec->pid = ev->pid;
    rec->tid = (unsigned long)ev->tid;
  }

  rec->alloc_bytes = otlp_rec_bytes(rec);
  otlp_rec_push(rec);
}

/* ---- OTLP HTTP 发送（独立线程 + libcurl，keep-alive 由 easy handle 复用） ---- */

static size_t otlp_discard_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

static int otlp_http_post(CURL *h, struct curl_slist *hdrs,
                         const uint8_t *body, size_t len, long timeout_ms,
                         long *http_code)
{
  curl_easy_setopt(h, CURLOPT_URL, g_log_otlp.endpoint);
  curl_easy_setopt(h, CURLOPT_POST, 1L);
  curl_easy_setopt(h, CURLOPT_POSTFIELDS, body);
  curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)len);
  curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);
  curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, otlp_discard_cb);
  curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, g_log_otlp.verify ? 1L : 0L);
  curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, g_log_otlp.verify ? 2L : 0L);
  if (g_log_otlp.ca[0]) curl_easy_setopt(h, CURLOPT_CAINFO, g_log_otlp.ca);
  curl_easy_setopt(h, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  curl_easy_setopt(h, CURLOPT_TCP_KEEPALIVE, 1L);

  CURLcode cc = curl_easy_perform(h);
  if (cc != CURLE_OK) {
    *http_code = -1;
    return -1;
  }
  long code = 0;
  curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code);
  *http_code = code;
  return 0;
}

/* OTLP 规范：429/502/503/504 可重试，其余 4xx 不重试 */
static int otlp_code_retryable(long code)
{
  return code == 429 || code == 502 || code == 503 || code == 504;
}

static void otlp_take_batch(otlp_sink_t *s, otlp_batch_t *out, int take_all)
{
  memset(out, 0, sizeof(*out));
  while (s->head) {
    otlp_rec_t *r = s->head;
    if (!take_all) {
      if (out->records >= (size_t)g_log_otlp.batch_max_records) break;
      if (out->records > 0 && out->bytes + r->alloc_bytes > g_log_otlp.batch_max_bytes) break;
    }
    s->head = r->next;
    if (!s->head) s->tail = NULL;
    r->next = NULL;
    if (out->tail) out->tail->next = r;
    else out->head = r;
    out->tail = r;
    out->bytes += r->alloc_bytes;
    out->records++;
    s->bytes -= r->alloc_bytes;
    if (s->records) s->records--;
  }
}

static void otlp_merge_batch(otlp_batch_t *dst, const otlp_batch_t *src)
{
  if (!src->head) return;
  if (dst->tail) dst->tail->next = src->head;
  else dst->head = src->head;
  dst->tail = src->tail;
  dst->bytes += src->bytes;
  dst->records += src->records;
}

static int otlp_send_batch(CURL *h, struct curl_slist *hdrs, otlp_batch_t *b, long timeout_ms)
{
  uint8_t *payload = NULL;
  size_t plen = 0;
  long code = -1;
  int rc = -1;

  if (otlp_encode_request(b, &payload, &plen) == 0 && plen > 0) {
    if (otlp_http_post(h, hdrs, payload, plen, timeout_ms, &code) == 0) {
      rc = (int)code;
    }
    free(payload);
  } else {
    rc = 400;   /* 编码失败按不可重试处理 */
  }
  if (rc >= 200 && rc < 300) return 0;
  return rc;
}

static void otlp_backoff_wait(int attempt)
{
  if (attempt < 1) attempt = 1;
  if (attempt > 6) attempt = 6;
  unsigned ms = 1000u << (attempt - 1);
  if (ms > 30000u) ms = 30000u;
  /* uv_cond_timedwait 的参数是相对时长（内部会叠加 uv_hrtime） */
  uv_mutex_lock(&g_otlp.mu);
  if (!g_otlp.stop) uv_cond_timedwait(&g_otlp.cond, &g_otlp.mu, (uint64_t)ms * 1000000ULL);
  uv_mutex_unlock(&g_otlp.mu);
}

static void otlp_thread_main(void *arg)
{
  (void)arg;
  g_current_worker_id = -1;
  CURL *h = curl_easy_init();
  if (!h) {
    fprintf(stderr, "otlp: curl_easy_init failed\n");
    return;
  }
  struct curl_slist *hdrs = NULL;
  hdrs = curl_slist_append(hdrs, "Content-Type: application/x-protobuf");
  hdrs = curl_slist_append(hdrs, "Accept: application/x-protobuf");
  for (int i = 0; i < g_log_otlp.nheaders; i++) {
    char line[640];
    snprintf(line, sizeof(line), "%s: %s",
             g_log_otlp.headers[i].name, g_log_otlp.headers[i].value);
    hdrs = curl_slist_append(hdrs, line);
  }

  otlp_batch_t retry = { 0 };
  int retry_count = 0;
  g_otlp.last_send_ns = uv_hrtime();

  for (;;) {
    otlp_batch_t b = { 0 };
    int stopping;

    uv_mutex_lock(&g_otlp.mu);
    while (!g_otlp.stop) {
      if (retry.head) break;              /* 重试批次优先，不等待新数据 */
      if (g_otlp.flush_req) break;
      if (g_otlp.records == 0) {
        uv_cond_wait(&g_otlp.cond, &g_otlp.mu);
        continue;
      }
      if (g_otlp.records >= (size_t)g_log_otlp.batch_max_records ||
          g_otlp.bytes >= g_log_otlp.batch_max_bytes) break;
      uint64_t deadline = g_otlp.last_send_ns +
                          (uint64_t)g_log_otlp.flush_ms * 1000000ULL;
      uint64_t now2 = uv_hrtime();
      if (now2 >= deadline) break;
      uv_cond_timedwait(&g_otlp.cond, &g_otlp.mu, deadline - now2);
    }
    stopping = g_otlp.stop;
    otlp_take_batch(&g_otlp, &b, stopping);
    g_otlp.flush_req = 0;
    g_otlp.last_send_ns = uv_hrtime();
    uv_mutex_unlock(&g_otlp.mu);

    if (stopping) {
      /* 关闭：合并重试批次与剩余队列，用较短超时做最后一次尝试 */
      otlp_merge_batch(&b, &retry);
      memset(&retry, 0, sizeof(retry));
      if (b.head) {
        int rc = otlp_send_batch(h, hdrs, &b, 2000);
        if (rc == 0) g_otlp.sent += b.records;
        else g_otlp.failed += b.records;
        otlp_batch_free(&b);
      }
      break;
    }

    if (retry.head) {
      if (retry_count >= g_log_otlp.max_retries) {
        g_otlp.failed += retry.records;
        otlp_batch_free(&retry);
        retry_count = 0;
        continue;
      }
      int rc = otlp_send_batch(h, hdrs, &retry, g_log_otlp.timeout_ms);
      if (rc == 0) {
        g_otlp.sent += retry.records;
        otlp_batch_free(&retry);
        retry_count = 0;
      } else if (rc > 0 && rc < 500 && !otlp_code_retryable(rc)) {
        g_otlp.failed += retry.records;
        otlp_batch_free(&retry);
        retry_count = 0;
      } else {
        retry_count++;
        otlp_backoff_wait(retry_count);
      }
      continue;
    }

    if (b.head) {
      int rc = otlp_send_batch(h, hdrs, &b, g_log_otlp.timeout_ms);
      if (rc == 0) {
        g_otlp.sent += b.records;
        otlp_batch_free(&b);
      } else if (rc > 0 && rc < 500 && !otlp_code_retryable(rc)) {
        g_otlp.failed += b.records;
        otlp_batch_free(&b);
      } else {
        retry = b;
        memset(&b, 0, sizeof(b));
        retry_count = 1;
        otlp_backoff_wait(retry_count);
      }
    }
  }

  curl_slist_free_all(hdrs);
  curl_easy_cleanup(h);
}

static int otlp_start(void)
{
  if (!g_log_otlp.enabled) return 0;
  memset(&g_otlp, 0, sizeof(g_otlp));
  uv_mutex_init(&g_otlp.mu);
  uv_cond_init(&g_otlp.cond);
  if (uv_thread_create(&g_otlp.thread, otlp_thread_main, NULL) != 0) {
    fprintf(stderr, "otlp: uv_thread_create failed\n");
    uv_cond_destroy(&g_otlp.cond);
    uv_mutex_destroy(&g_otlp.mu);
    return -1;
  }
  g_otlp.started = 1;
  return 0;
}

static void otlp_shutdown(void)
{
  if (!g_otlp.started) return;
  uv_mutex_lock(&g_otlp.mu);
  g_otlp.stop = 1;
  uv_cond_signal(&g_otlp.cond);
  uv_mutex_unlock(&g_otlp.mu);
  uv_thread_join(&g_otlp.thread);
  g_otlp.started = 0;
  uv_cond_destroy(&g_otlp.cond);
  uv_mutex_destroy(&g_otlp.mu);
}

/* ==================== 日志三通道：syslog ==================== */

static int syslog_sev(int level)
{
  switch (level) {
    case LOG_ERROR: return 3;   /* err */
    case LOG_WARN:  return 4;   /* warning */
    case LOG_INFO:  return 6;   /* info */
    default:        return 7;   /* debug */
  }
}

static void syslog_enqueue(int severity, const char *msg, size_t len)
{
  if (!g_log_syslog.enabled || g_log_shutting_down) return;
  while (len && (msg[len - 1] == '\n' || msg[len - 1] == '\r')) len--;

  time_t now = time(NULL);
  struct tm tm;
  localtime_r(&now, &tm);
  char host[128] = { 0 };
  gethostname(host, sizeof(host) - 1);
  int pri = g_log_syslog.facility * 8 + severity;
  char hdr[600];

  if (g_log_syslog.format == 0) {
    /* RFC 5424 */
    struct timespec rt;
    clock_gettime(CLOCK_REALTIME, &rt);
    long off = tm.tm_gmtoff;
    int sign = off < 0 ? '-' : '+';
    long aoff = off < 0 ? -off : off;
    snprintf(hdr, sizeof(hdr),
             "<%d>1 %04d-%02d-%02dT%02d:%02d:%02d.%03ld%c%02ld:%02ld %s %s %d - - ",
             pri, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, rt.tv_nsec / 1000000,
             sign, aoff / 3600, (aoff % 3600) / 60,
             host[0] ? host : "-", g_log_syslog.tag, (int)getpid());
  } else {
    /* RFC 3164 */
    char tsbuf[64];
    strftime(tsbuf, sizeof(tsbuf), "%b %e %H:%M:%S", &tm);
    snprintf(hdr, sizeof(hdr), "<%d>%s %s %s[%d]: ", pri, tsbuf,
             host[0] ? host : "-", g_log_syslog.tag, (int)getpid());
  }

  size_t hl = strlen(hdr);
  if (hl >= 4096) hl = 4095;
  size_t max_msg = 4096 - hl;
  if (len > max_msg) len = max_msg;
  size_t total = hl + len;

  char *m = (char *)malloc(total + 1);
  if (!m) { g_syslog.dropped++; return; }
  memcpy(m, hdr, hl);
  memcpy(m + hl, msg, len);
  m[total] = 0;

  syslog_msg_t *sm = (syslog_msg_t *)calloc(1, sizeof(*sm));
  if (!sm) { free(m); g_syslog.dropped++; return; }
  sm->severity = severity;
  sm->ts = now;
  sm->msg = m;
  sm->len = total;
  sm->alloc_bytes = sizeof(*sm) + total;

  int sig = 0;
  uv_mutex_lock(&g_syslog.mu);
  int was_empty = g_syslog.head == NULL;
  if (sm->alloc_bytes > g_log_syslog.queue_max_bytes) {
    g_syslog.dropped++;
    uv_mutex_unlock(&g_syslog.mu);
    free(sm->msg);
    free(sm);
    return;
  }
  while (g_syslog.bytes + sm->alloc_bytes > g_log_syslog.queue_max_bytes && g_syslog.head) {
    syslog_msg_t *old = g_syslog.head;
    g_syslog.head = old->next;
    if (!g_syslog.head) g_syslog.tail = NULL;
    g_syslog.bytes -= old->alloc_bytes;
    if (g_syslog.records) g_syslog.records--;
    g_syslog.dropped++;
    free(old->msg);
    free(old);
  }
  if (g_syslog.tail) g_syslog.tail->next = sm;
  else g_syslog.head = sm;
  g_syslog.tail = sm;
  g_syslog.bytes += sm->alloc_bytes;
  g_syslog.records++;
  if (was_empty) sig = 1;
  uv_mutex_unlock(&g_syslog.mu);
  if (sig) uv_cond_signal(&g_syslog.cond);
}

typedef struct {
  int fd;
  int connected;
  int is_stream;
  int is_tls;
  int dgram;
  int addr_ok;
  uint64_t next_connect_ns;
  struct sockaddr_storage addr;
  int addrlen;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt ca;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context drbg;
  int tls_inited;
  mbedtls_net_context net;
} syslog_conn_t;

static int syslog_resolve(syslog_conn_t *sc)
{
  if (g_log_syslog.transport == 3) {
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    if (!g_log_syslog.path[0]) return -1;
    if (strlen(g_log_syslog.path) >= sizeof(sun.sun_path)) return -1;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", g_log_syslog.path);
    memcpy(&sc->addr, &sun, sizeof(sun));
    sc->addrlen = (int)sizeof(sun);
    sc->addr_ok = 1;
    return 0;
  }

  char portstr[32];
  snprintf(portstr, sizeof(portstr), "%d", g_log_syslog.port);
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = sc->dgram ? SOCK_DGRAM : SOCK_STREAM;
  struct addrinfo *res = NULL;
  if (getaddrinfo(g_log_syslog.host, portstr, &hints, &res) != 0 || !res) return -1;
  memcpy(&sc->addr, res->ai_addr, res->ai_addrlen);
  sc->addrlen = (int)res->ai_addrlen;
  freeaddrinfo(res);
  sc->addr_ok = 1;
  return 0;
}

static void syslog_disconnect(syslog_conn_t *sc)
{
  if (sc->is_tls && sc->connected) {
    mbedtls_ssl_close_notify(&sc->ssl);
    mbedtls_ssl_session_reset(&sc->ssl);
  }
  if (sc->fd >= 0) close(sc->fd);
  sc->fd = -1;
  sc->connected = 0;
}

static int syslog_connect(syslog_conn_t *sc)
{
  int fd = socket(sc->addr.ss_family, sc->dgram ? SOCK_DGRAM : SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  if (connect(fd, (struct sockaddr *)&sc->addr, sc->addrlen) != 0) {
    fprintf(stderr, "syslog: connect %s:%d failed: %s\n",
            g_log_syslog.host, g_log_syslog.port, strerror(errno));
    close(fd);
    return -1;
  }

  if (sc->is_tls) {
    sc->net.fd = fd;
    mbedtls_ssl_set_hostname(&sc->ssl, g_log_syslog.host);
    mbedtls_ssl_set_bio(&sc->ssl, &sc->net, mbedtls_net_send, mbedtls_net_recv, NULL);
    int rc;
    while ((rc = mbedtls_ssl_handshake(&sc->ssl)) != 0) {
      if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
        fprintf(stderr, "syslog: TLS handshake failed: -0x%04x\n", (unsigned)(-rc));
        close(fd);
        return -1;
      }
    }
  }

  sc->fd = fd;
  sc->connected = 1;
  return 0;
}

static int syslog_tls_setup(syslog_conn_t *sc)
{
  mbedtls_ssl_init(&sc->ssl);
  mbedtls_ssl_config_init(&sc->conf);
  mbedtls_x509_crt_init(&sc->ca);
  mbedtls_entropy_init(&sc->entropy);
  mbedtls_ctr_drbg_init(&sc->drbg);
  sc->tls_inited = 1;

  int rc = mbedtls_ctr_drbg_seed(&sc->drbg, mbedtls_entropy_func, &sc->entropy, NULL, 0);
  if (rc != 0) return -1;
  rc = mbedtls_ssl_config_defaults(&sc->conf, MBEDTLS_SSL_IS_CLIENT,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc != 0) return -1;
  mbedtls_ssl_conf_rng(&sc->conf, mbedtls_ctr_drbg_random, &sc->drbg);
  mbedtls_ssl_conf_min_tls_version(&sc->conf, MBEDTLS_SSL_VERSION_TLS1_2);

  if (g_log_syslog.verify) {
    const char *ca = g_log_syslog.ca[0] ? g_log_syslog.ca
                                        : "/etc/ssl/certs/ca-certificates.crt";
    rc = mbedtls_x509_crt_parse_file(&sc->ca, ca);
    if (rc < 0) {
      fprintf(stderr, "syslog: failed to parse CA %s\n", ca);
      return -1;
    }
    mbedtls_ssl_conf_ca_chain(&sc->conf, &sc->ca, NULL);
    mbedtls_ssl_conf_authmode(&sc->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  } else {
    mbedtls_ssl_conf_authmode(&sc->conf, MBEDTLS_SSL_VERIFY_NONE);
  }

  rc = mbedtls_ssl_setup(&sc->ssl, &sc->conf);
  if (rc != 0) return -1;
  return 0;
}

static int syslog_send_one(syslog_conn_t *sc, const syslog_msg_t *m)
{
  char frame[32];
  int fl = 0;
  if (sc->is_stream) {
    /* RFC 6587 octet-counting: "<len> <msg>" */
    fl = snprintf(frame, sizeof(frame), "%zu ", m->len);
  }

  if (sc->is_tls) {
    if (fl > 0) {
      int n = mbedtls_ssl_write(&sc->ssl, (const unsigned char *)frame, (size_t)fl);
      if (n != fl) return -1;
    }
    int n = mbedtls_ssl_write(&sc->ssl, (const unsigned char *)m->msg, m->len);
    return (n == (int)m->len) ? 0 : -1;
  }

  if (sc->is_stream) {
    size_t off = 0;
    while (off < (size_t)fl) {
      ssize_t n = write(sc->fd, frame + off, (size_t)fl - off);
      if (n <= 0) {
        if (errno == EINTR) continue;
        return -1;
      }
      off += (size_t)n;
    }
  }
  size_t off = 0;
  while (off < m->len) {
    ssize_t n = write(sc->fd, m->msg + off, m->len - off);
    if (n <= 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    off += (size_t)n;
  }
  return 0;
}

static void syslog_thread_main(void *arg)
{
  (void)arg;
  g_current_worker_id = -1;
  syslog_conn_t sc;
  memset(&sc, 0, sizeof(sc));
  sc.fd = -1;
  sc.dgram = (g_log_syslog.transport == 0 || g_log_syslog.transport == 3);
  sc.is_stream = !sc.dgram;
  sc.is_tls = (g_log_syslog.transport == 2);
  if (sc.is_tls && syslog_tls_setup(&sc) != 0) {
    fprintf(stderr, "syslog: TLS setup failed, dropping messages\n");
    sc.is_tls = 0;
    sc.dgram = 1;   /* 无法发送，走丢弃路径 */
  }

  for (;;) {
    uv_mutex_lock(&g_syslog.mu);
    while (!g_syslog.stop && g_syslog.records == 0 && !g_syslog.reload) {
      uv_cond_wait(&g_syslog.cond, &g_syslog.mu);
    }
    int do_reload = g_syslog.reload;
    g_syslog.reload = 0;
    syslog_msg_t *list = g_syslog.head;
    g_syslog.head = NULL;
    g_syslog.tail = NULL;
    g_syslog.records = 0;
    g_syslog.bytes = 0;
    int stopping = g_syslog.stop;
    uv_mutex_unlock(&g_syslog.mu);

    if (do_reload) {
      syslog_disconnect(&sc);
      sc.addr_ok = 0;
      sc.next_connect_ns = 0;
    }
    if (!list) {
      if (stopping) break;
      continue;
    }

    uint64_t now = uv_hrtime();
    if (!sc.addr_ok && now >= sc.next_connect_ns) {
      if (syslog_resolve(&sc) != 0) {
        sc.next_connect_ns = now + (uint64_t)g_log_syslog.reconnect_ms * 1000000ULL;
      }
    }
    if (sc.addr_ok && !sc.connected && now >= sc.next_connect_ns) {
      if (syslog_connect(&sc) != 0) {
        sc.next_connect_ns = now + (uint64_t)g_log_syslog.reconnect_ms * 1000000ULL;
      }
    }

    syslog_msg_t *m = list;
    while (m) {
      syslog_msg_t *next = m->next;
      int ok = 0;
      if (sc.connected) {
        if (syslog_send_one(&sc, m) == 0) {
          ok = 1;
        } else {
          syslog_disconnect(&sc);
          sc.next_connect_ns = uv_hrtime() + (uint64_t)g_log_syslog.reconnect_ms * 1000000ULL;
        }
      }
      if (ok) g_syslog.sent++;
      else g_syslog.failed++;
      free(m->msg);
      free(m);
      m = next;
    }

    if (stopping) break;
  }

  syslog_disconnect(&sc);
  if (sc.tls_inited) {
    mbedtls_ssl_free(&sc.ssl);
    mbedtls_ssl_config_free(&sc.conf);
    mbedtls_x509_crt_free(&sc.ca);
    mbedtls_entropy_free(&sc.entropy);
    mbedtls_ctr_drbg_free(&sc.drbg);
  }
}

static int syslog_start(void)
{
  if (!g_log_syslog.enabled) return 0;
  memset(&g_syslog, 0, sizeof(g_syslog));
  uv_mutex_init(&g_syslog.mu);
  uv_cond_init(&g_syslog.cond);
  if (uv_thread_create(&g_syslog.thread, syslog_thread_main, NULL) != 0) {
    fprintf(stderr, "syslog: uv_thread_create failed\n");
    uv_cond_destroy(&g_syslog.cond);
    uv_mutex_destroy(&g_syslog.mu);
    return -1;
  }
  g_syslog.started = 1;
  return 0;
}

static void syslog_shutdown(void)
{
  if (!g_syslog.started) return;
  uv_mutex_lock(&g_syslog.mu);
  g_syslog.stop = 1;
  uv_cond_signal(&g_syslog.cond);
  uv_mutex_unlock(&g_syslog.mu);
  uv_thread_join(&g_syslog.thread);
  g_syslog.started = 0;
  uv_cond_destroy(&g_syslog.cond);
  uv_mutex_destroy(&g_syslog.mu);
}

static void log_init(void)
{
  /* 多 worker 各自写同一文件时，内置 rotate 由多个 sink 同时 rename/truncate 会竞态；
   * P0 先禁用内置 rotate（外部 logrotate 仍可用，因为每批 reopen O_APPEND）。 */
  if (g_worker_count > 1 &&
      (g_log_file.rotate_ms > 0 || g_log_file.rotate_size > 0)) {
    if (g_current_worker_id == 0)
      fprintf(stderr, "log: built-in rotate disabled with workers > 1\n");
    g_log_file.rotate_ms = 0;
    g_log_file.rotate_size = 0;
  }

  /* file 通道：每类日志的开关在 parse_log 里已与路径做一致性校验 */
  if (g_log_file.enabled && g_log_file.access_on && g_log_file.access_path[0]) {
    log_sink_init(&g_access_log, g_log_file.access_path, g_log_file.max_bytes,
                  g_log_file.flush_ms, g_log_file.rotate_ms, g_log_file.rotate_size,
                  g_log_file.rotate_keep);
  }
  if (g_log_file.enabled && g_log_file.error_on && g_log_file.error_path[0]) {
    log_sink_init(&g_error_log, g_log_file.error_path, g_log_file.max_bytes,
                  g_log_file.flush_ms, g_log_file.rotate_ms, g_log_file.rotate_size,
                  g_log_file.rotate_keep);
  }
  if (g_worker_count <= 1) {
    if (otlp_start() != 0) g_log_otlp.enabled = 0;
    if (syslog_start() != 0) g_log_syslog.enabled = 0;
  } else {
    /* P0：多 worker 只启用 file 通道。OTLP/syslog 若每 worker 各自起线程会重复发送，
     * 统一收集/发送留到后续阶段。 */
    g_log_otlp.enabled = 0;
    g_log_syslog.enabled = 0;
  }
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
  /* 本地文件是权威副本，先落盘；远端通道最后尽力 flush 剩余队列 */
  log_sink_flush_sync(&g_access_log);
  log_sink_flush_sync(&g_error_log);
  otlp_shutdown();
  syslog_shutdown();
}

static void log_error(int level, const char *fmt, ...)
{
  int lv = (level >= LOG_ERROR && level <= LOG_DEBUG) ? level : LOG_ERROR;

  int file_level = g_log_file.level >= 0 ? g_log_file.level : g_log_level;
  int otlp_level = g_log_otlp.level >= 0 ? g_log_otlp.level : g_log_level;
  int syslog_level = g_log_syslog.level >= 0 ? g_log_syslog.level : g_log_level;

  int want_file = g_log_pipeline
      ? (g_log_file.enabled && g_log_file.error_on && level <= file_level)
      : (g_error_log.enabled && level <= file_level);
  int want_otlp = g_log_otlp.enabled && g_log_otlp.error_on && level <= otlp_level;
  int want_syslog = g_log_syslog.enabled && g_log_syslog.error_on && level <= syslog_level;
  int want_stderr = !want_file && level <= g_log_level;
  if (!want_file && !want_otlp && !want_syslog && !want_stderr) return;

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
  char line[2300];
  snprintf(line, sizeof(line), "%04d/%02d/%02d %02d:%02d:%02d [%s] %d#%lu: %s\n",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec, log_level_name(lv),
           (int)getpid(), (unsigned long)uv_thread_self(), msg);
  size_t line_len = strlen(line);

  if (g_log_pipeline) {
    log_ring_t *lr = log_ring_for(1);
    uint8_t targets = (uint8_t)((want_file ? LOGP_TARGET_FILE : 0) |
                                (want_otlp ? LOGP_TARGET_OTLP : 0) |
                                (want_syslog ? LOGP_TARGET_SYSLOG : 0));
    if (lr && targets) {
      if (log_event_emit(lr, 2, (uint8_t)lv, targets, 0, 0, 0,
                         (int32_t)getpid(), (uint32_t)uv_thread_self(),
                         NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                         line, line_len) != 0) {
        fputs(line, stderr);
      }
    } else if (!lr || want_stderr) {
      fputs(line, stderr);
    }
    return;
  }

  if (want_file) log_sink_append(&g_error_log, line, line_len);
  if (want_stderr) fputs(line, stderr);
  if (want_otlp) otlp_enqueue_error(lv, line, line_len);
  if (want_syslog) syslog_enqueue(syslog_sev(lv), line, line_len);
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
  if (r->access_logged) return;
  if (!r->method && !r->head_copy && r->status == 0) return;

  int want_file = g_log_pipeline
      ? (g_log_file.enabled && g_log_file.access_on)
      : g_access_log.enabled;
  int want_otlp = g_log_otlp.enabled && g_log_otlp.access_on;
  int want_syslog = g_log_syslog.enabled && g_log_syslog.access_on;
  r->access_logged = 1;
  if (!want_file && !want_otlp && !want_syslog) return;

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

  if (b.p) {
    if (g_log_pipeline) {
      log_ring_t *lr = log_ring_for(0);
      uint8_t targets = (uint8_t)((want_file ? LOGP_TARGET_FILE : 0) |
                                  (want_otlp ? LOGP_TARGET_OTLP : 0) |
                                  (want_syslog ? LOGP_TARGET_SYSLOG : 0));
      if (lr && targets) {
        log_event_emit(lr, 1, LOG_INFO, targets, status, r->written, r->minor, 0, 0,
                       r->method, r->method_len, r->path, r->path_len,
                       c->remote_addr, strlen(c->remote_addr),
                       ref, ref_len, ua, ua_len, b.p, b.len);
      }
      free(b.p);
      return;
    }
    if (want_file) log_sink_append(&g_access_log, b.p, b.len);
    if (want_otlp) {
      otlp_enqueue_access(r, c->remote_addr, status, r->written,
                          ref, ref_len, ua, ua_len, b.p, b.len);
    }
    if (want_syslog) syslog_enqueue(6, b.p, b.len);   /* info */
  }
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
  lua_pushboolean(co, r->body_cl > 0 || r->chunked);
  lua_setfield(co, -2, "has_body");
  lua_pushinteger(co, (lua_Integer)(r->chunked ? 0 : r->body_cl));
  lua_setfield(co, -2, "body_size");
  lua_pushboolean(co, r->chunked || r->body_cl > g_auto_buffer_body);
  lua_setfield(co, -2, "streaming");
  lua_pushboolean(co, r->chunked);
  lua_setfield(co, -2, "chunked");
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
    } else if (r->chunked ? r->body_eof : (r->body_received >= r->body_cl)) {
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
  /* Transfer-Encoding: 只接受单个 "chunked"（不支持 gzip 等其它 coding） */
  int te_chunked = 0, te_count = 0;
  for (size_t i = 0; i < num_headers; i++) {
    if (!r->headers[i].name || r->headers[i].name_len != 17) continue;
    if (strncasecmp(r->headers[i].name, "transfer-encoding", 17) != 0) continue;
    te_count++;
    const char *v = r->headers[i].value;
    size_t vl = r->headers[i].value_len;
    while (vl && (v[0] == ' ' || v[0] == '\t')) { v++; vl--; }
    while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) vl--;
    if (vl == 7 && strncasecmp(v, "chunked", 7) == 0 && te_chunked == 0) {
      te_chunked = 1;
    } else {
      te_chunked = -1;
    }
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
  if (te_count > 0) {
    if (minor < 1) { send_error(c, 400, "Transfer-Encoding requires HTTP/1.1"); return 0; }
    if (te_chunked != 1) { send_error(c, 400, "unsupported Transfer-Encoding"); return 0; }
    if (n_cl > 0) { send_error(c, 400, "Content-Length with Transfer-Encoding"); return 0; }
    r->chunked = 1;
  }
  if (!r->chunked && cl > 0 && (unsigned long long)cl > (unsigned long long)max_body_stream) {
    send_error(c, 413, "body too large");
    return 0;
  }
  r->body_cl = (!r->chunked && cl > 0) ? (size_t)cl : 0;
  r->auto_buffer = !r->chunked && r->body_cl <= g_auto_buffer_body;
  r->chunk_state = 0;
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

static int consume_chunked(conn_t *c)
{
  request_t *r = &c->req;

  while (!c->closing) {
    if (r->chunk_state == 0) {           /* chunk-size CRLF */
      const char *nl = (const char *)memchr(c->buf, '\n', c->len);
      if (!nl) {
        if (c->len > 1024) { send_error(c, 400, "bad chunk size"); return 0; }
        return 0;
      }
      size_t line_len = (size_t)(nl - c->buf) + 1;
      size_t i = 0;
      unsigned long long sz = 0;
      int digits = 0;
      while (i < line_len) {
        char ch = c->buf[i];
        if (ch == ';') break;            /* chunk extension 忽略 */
        if (ch == '\r' || ch == '\n') break;
        int v;
        if (ch >= '0' && ch <= '9') v = ch - '0';
        else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
        else { send_error(c, 400, "bad chunk size"); return 0; }
        sz = sz * 16 + (unsigned long long)v;
        if (sz > (1ULL << 40)) { send_error(c, 400, "chunk too large"); return 0; }
        digits++;
        i++;
      }
      if (!digits) { send_error(c, 400, "bad chunk size"); return 0; }
      buf_consume(c, line_len);
      if (sz == 0) {
        r->chunk_state = 3;             /* trailers */
      } else {
        r->chunk_remaining = (size_t)sz;
        r->chunk_state = 1;
      }
      continue;
    }

    if (r->chunk_state == 1) {           /* chunk data */
      if (c->len == 0) return 0;
      size_t n = c->len < r->chunk_remaining ? c->len : r->chunk_remaining;
      if (!r->discarding && r->chunk_total + n > max_body_stream) {
        send_error(c, 413, "body too large");
        return 0;
      }
      if (r->discarding) {
        r->body_received += n;
        r->chunk_total += n;
      } else if (r->waiting_read) {
        lua_pushlstring(r->co, c->buf, n);
        r->waiting_read = 0;
        r->body_received += n;
        r->body_delivered += n;
        r->chunk_total += n;
        buf_consume(c, n);
        int rc = lua_resume(r->co, 1);
        on_resume(c, rc);
        if (c->closing) return 0;
      } else {
        if (append_body_buf(r, c->buf, n) != 0) { close_conn(c); return 0; }
        r->body_received += n;
        r->chunk_total += n;
        buf_consume(c, n);
        if (!c->read_paused && r->body_len >= g_read_high_water) {
          c->read_paused = 1;
          uv_read_stop((uv_stream_t *)&c->handle);
        }
      }
      if (r->discarding) buf_consume(c, n);
      r->chunk_remaining -= n;
      if (r->chunk_remaining == 0) r->chunk_state = 2;
      continue;
    }

    if (r->chunk_state == 2) {           /* CRLF after data */
      if (c->len < 2) return 0;
      if (c->buf[0] != '\r' || c->buf[1] != '\n') {
        send_error(c, 400, "bad chunk terminator");
        return 0;
      }
      buf_consume(c, 2);
      r->chunk_state = 0;
      continue;
    }

    if (r->chunk_state == 3) {           /* trailer section 以空行结束 */
      size_t end = 0;
      int found = 0;
      if (c->len >= 2 && c->buf[0] == '\r' && c->buf[1] == '\n') {
        end = 2;
        found = 1;
      } else {
        for (size_t i = 0; i + 3 < c->len; i++) {
          if (c->buf[i] == '\r' && c->buf[i + 1] == '\n' &&
              c->buf[i + 2] == '\r' && c->buf[i + 3] == '\n') {
            end = i + 4;
            found = 1;
            break;
          }
        }
      }
      if (!found) {
        if (c->len > 8192 + 4) { send_error(c, 400, "trailer too large"); return 0; }
        return 0;
      }
      buf_consume(c, end);
      r->chunk_state = 4;
      r->body_eof = 1;
      if (r->waiting_read) {
        lua_pushnil(r->co);
        r->waiting_read = 0;
        int rc = lua_resume(r->co, 1);
        on_resume(c, rc);
        if (c->closing) return 0;
      }
      if (r->discarding && !c->closing) {
        request_finalize(c);
        return 1;
      }
      return 1;
    }

    return 1;                            /* done */
  }
  return 0;
}

static int consume_body(conn_t *c)
{
  request_t *r = &c->req;

  if (r->chunked) return consume_chunked(c);

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
    if (r->discarding) {
      request_finalize(c);
      return 1;
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

  if (r->chunked ? !r->body_eof : (r->body_received < r->body_cl)) {
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

/* 配置解析错误：reload 模式用 longjmp 返回，启动/check 模式直接退出 */
static jmp_buf *g_cfg_jmp;
static char g_cfg_err[1024];

static void die(const char *fmt, ...)
{
  char msg[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  if (g_cfg_jmp) {
    snprintf(g_cfg_err, sizeof(g_cfg_err), "%s", msg);
    longjmp(*g_cfg_jmp, 1);
  }
  fprintf(stderr, "config error: %s\n", msg);
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
  /* SO_REUSEPORT 下每个 worker 各自 bind；端口 0 会得到不同端口 */
  if (g_worker_count > 1 && port == 0)
    die("listen port 0 requires workers = 1");
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
  __atomic_store_n(&s->refs, 1, __ATOMIC_RELEASE);
  return s;
}

static void revoked_store_free(revoked_store_t *s)
{
  if (!s) return;
  free(s->keys);
  free(s->used);
  free(s);
}

/* 旧表延迟回收：最后一个引用释放后进入 retire 队列，由定时器/关闭路径统一 free */
static void revoked_store_unref(revoked_store_t *s)
{
  if (!s) return;
  if (__atomic_sub_fetch(&s->refs, 1, __ATOMIC_ACQ_REL) != 0) return;
  if (!g_revoke_mu_inited) {
    revoked_store_free(s);
    return;
  }
  uv_mutex_lock(&g_revoke_mu);
  s->next_retire = g_revoke_retire;
  g_revoke_retire = s;
  uv_mutex_unlock(&g_revoke_mu);
}

static void revocation_reclaim(void)
{
  if (!g_revoke_mu_inited) return;
  uv_mutex_lock(&g_revoke_mu);
  revoked_store_t *list = g_revoke_retire;
  g_revoke_retire = NULL;
  uv_mutex_unlock(&g_revoke_mu);
  while (list) {
    revoked_store_t *next = list->next_retire;
    revoked_store_free(list);
    list = next;
  }
}

static revoked_store_t *revocation_get_ref(void)
{
  if (!g_revoke_mu_inited) return NULL;
  uv_mutex_lock(&g_revoke_mu);
  revoked_store_t *s = __atomic_load_n(&g_revoked, __ATOMIC_ACQUIRE);
  if (s) __atomic_add_fetch(&s->refs, 1, __ATOMIC_RELAXED);
  uv_mutex_unlock(&g_revoke_mu);
  return s;
}

static void revocation_publish(revoked_store_t *ns)
{
  uv_mutex_lock(&g_revoke_mu);
  revoked_store_t *old = __atomic_exchange_n(&g_revoked, ns, __ATOMIC_ACQ_REL);
  __atomic_store_n(&g_revocation.loaded, 1, __ATOMIC_RELEASE);
  uv_mutex_unlock(&g_revoke_mu);
  revoked_store_unref(old);
}

static void revocation_mutex_init_once(void)
{
  if (!g_revoke_mu_inited) {
    uv_mutex_init(&g_revoke_mu);
    g_revoke_mu_inited = 1;
  }
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

static revoked_store_t *revocation_load_file(const char *path, size_t max_bytes,
                                            size_t max_entries, char *err, size_t errlen)
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
  if (sz < 0 || (size_t)sz > max_bytes) {
    if (err) snprintf(err, errlen, "%s too large (max %zu bytes)", path, max_bytes);
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
    if (s->count >= max_entries) { bad = 1; break; }
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
  char path[512];
  size_t max_bytes;
  size_t max_entries;
  char err[512];
} revocation_job_t;

static void revocation_work_cb(uv_work_t *req)
{
  revocation_job_t *j = (revocation_job_t *)req->data;
  j->store = revocation_load_file(j->path, j->max_bytes, j->max_entries,
                                  j->err, sizeof(j->err));
}

static void revocation_after_cb(uv_work_t *req, int status)
{
  revocation_job_t *j = (revocation_job_t *)req->data;
  (void)status;
  g_revocation_checking = 0;
  if (j->store) {
    revocation_publish(j->store);
    log_error(LOG_INFO, "revocation: loaded %zu entries (periodic)", j->store->count);
  } else {
    log_error(LOG_ERROR, "revocation: periodic refresh failed: %s", j->err);
  }
  free(j);
}

static void revocation_timer_cb(uv_timer_t *t)
{
  (void)t;
  revocation_reclaim();
  if (!g_revocation.enabled || g_revocation_checking) return;
  revocation_job_t *j = (revocation_job_t *)calloc(1, sizeof(*j));
  if (!j) return;
  j->work.data = j;
  snprintf(j->path, sizeof(j->path), "%s", g_revocation.source_file);
  j->max_bytes = g_revocation.max_bytes;
  j->max_entries = g_revocation.max_entries;
  g_revocation_checking = 1;
  if (uv_queue_work(loop, &j->work, revocation_work_cb, revocation_after_cb) != 0) {
    g_revocation_checking = 0;
    free(j);
    log_error(LOG_ERROR, "revocation: uv_queue_work refresh failed");
  }
}

static void revocation_init(void)
{
  revocation_mutex_init_once();
  if (__atomic_exchange_n(&g_revocation_inited, 1, __ATOMIC_ACQ_REL)) {
    /* 后续 worker 的 config_defaults_init 会把 loaded 清 0，这里恢复共享表状态 */
    if (__atomic_load_n(&g_revoked, __ATOMIC_ACQUIRE))
      __atomic_store_n(&g_revocation.loaded, 1, __ATOMIC_RELEASE);
    return;
  }
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
  revoked_store_t *ns = revocation_load_file(g_revocation.source_file,
                                             g_revocation.max_bytes,
                                             g_revocation.max_entries,
                                             err, sizeof(err));
  if (!ns) {
    log_error(LOG_ERROR, "revocation: initial load failed: %s", err);
    return;
  }
  revocation_publish(ns);
  log_error(LOG_INFO, "revocation: loaded %zu entries", ns->count);
}

/* mbedTLS 证书验证回调：只检查客户端叶子证书（depth 0） */
static int revocation_verify(void *p, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
  (void)p;
  if (!g_revocation.enabled || depth != 0) return 0;
  if (!__atomic_load_n(&g_revocation.loaded, __ATOMIC_ACQUIRE)) {
    if (g_revocation.reject_all) *flags |= MBEDTLS_X509_BADCERT_REVOKED;
    return 0;
  }
  revoked_store_t *s = revocation_get_ref();
  if (!s) return 0;
  uint8_t fp[32];
  if (mbedtls_sha256(crt->raw.p, crt->raw.len, fp, 0) == 0 &&
      revoked_store_contains(s, fp)) {
    *flags |= MBEDTLS_X509_BADCERT_REVOKED;
  }
  revoked_store_unref(s);
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
  tls_stamp_t *old_stamps;   /* 提交时的快照（work 线程不能读提交线程的 TLS） */
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
  if (tls_stamps_equal(j->old_stamps, st)) {
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
  free(j->old_stamps);
  free(j);
}

static void tls_check_timer_cb(uv_timer_t *t)
{
  (void)t;
  if (g_tls_checking || !g_tls_enabled || g_tls_path_count == 0) return;
  tls_check_job_t *j = (tls_check_job_t *)calloc(1, sizeof(*j));
  if (!j) return;
  j->work.data = j;
  size_t nst = g_tls_path_count ? g_tls_path_count : 1;
  j->old_stamps = (tls_stamp_t *)calloc(nst, sizeof(tls_stamp_t));
  if (!j->old_stamps) { free(j); return; }
  memcpy(j->old_stamps, g_tls_stamps, nst * sizeof(tls_stamp_t));
  g_tls_checking = 1;
  if (uv_queue_work(loop, &j->work, tls_check_work_cb, tls_check_after_cb) != 0) {
    g_tls_checking = 0;
    free(j->old_stamps);
    free(j);
    log_error(LOG_ERROR, "tls: uv_queue_work check failed");
  }
}

static void parse_tcp(lua_State *l, int sidx)
{
  /* 多 worker 必须让每个线程各自 bind 同一端口，SO_REUSEPORT 是硬性要求 */
  if (g_worker_count > 1) g_tcp.reuse_port = 1;

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

  /* 多 worker 必须让每个线程各自 bind 同一端口，SO_REUSEPORT 是硬性要求 */
  if (g_worker_count > 1) g_tcp.reuse_port = 1;
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

static int log_facility_num(const char *s)
{
  static const char *names[] = { "kern", "user", "mail", "daemon", "auth", "syslog",
                                 "lpr", "news", "uucp", "cron", "authpriv", "ftp" };
  if (!s || !s[0]) return 16;
  for (int i = 0; i < 12; i++) {
    if (strcasecmp(s, names[i]) == 0) return i;
  }
  if (strncasecmp(s, "local", 5) == 0) {
    int n = atoi(s + 5);
    if (n >= 0 && n <= 7) return 16 + n;
  }
  int v = atoi(s);
  if (v >= 0 && v <= 23) return v;
  die("log.syslog.facility must be 0..23, kern..ftp or local0..local7");
  return 16;
}

/* URL 只有 host（或 host/）时补默认 /v1/logs；自定义 path 原样保留 */
static void log_otlp_normalize_url(const char *url, char *out, size_t out_sz)
{
  if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
    die("log.otlp.endpoint must start with http:// or https://");
  }
  const char *p = strstr(url, "://") + 3;
  const char *slash = strchr(p, '/');
  if (!slash || slash[1] == 0) {
    size_t base = slash ? (size_t)(slash - url) : strlen(url);
    snprintf(out, out_sz, "%.*s/v1/logs", (int)base, url);
  } else {
    snprintf(out, out_sz, "%s", url);
  }
}

/* file 通道的 flush/max_buffer/rotate 参数（file 子表与旧平铺写法共用） */
static void parse_log_file_keys(lua_State *l, int idx, log_file_cfg_t *f)
{
  lua_getfield(l, idx, "flush_interval");
  if (lua_isnumber(l, -1)) {
    double sec = lua_tonumber(l, -1);
    int ms = (int)(sec * 1000);
    if (ms < 10) ms = 10;
    if (ms > 60000) ms = 60000;
    f->flush_ms = ms;
  }
  lua_pop(l, 1);

  long long v = cfg_ll(l, idx, "max_buffer", (long long)f->max_bytes);
  if (v > 0) f->max_bytes = (size_t)v;
  if (f->max_bytes < 4096) die("log.file.max_buffer too small");

  lua_getfield(l, idx, "rotate_interval");
  if (lua_isnumber(l, -1)) {
    double sec = lua_tonumber(l, -1);
    int ms = 0;
    if (sec > 0) {
      ms = (int)(sec * 1000);
      if (ms < 100) ms = 100;
      if (ms > 86400000) ms = 86400000;
    }
    f->rotate_ms = ms;
  }
  lua_pop(l, 1);

  v = cfg_ll(l, idx, "rotate_size", (long long)f->rotate_size);
  if (v >= 0) f->rotate_size = (size_t)v;
  v = cfg_ll(l, idx, "rotate_keep", f->rotate_keep);
  if (v >= 0) {
    if (v > 100) v = 100;
    f->rotate_keep = (int)v;
  }
}

static void parse_log(lua_State *l, int cfg)
{
  lua_getfield(l, cfg, "log");
  if (!lua_istable(l, -1)) { lua_pop(l, 1); return; }
  int li = lua_gettop(l);

  const char *lv = cfg_str(l, li, "level");
  if (lv) g_log_level = log_level_num(lv);

  /* ---------- file ---------- */
  lua_getfield(l, li, "file");
  if (lua_istable(l, -1)) {
    int fi = lua_gettop(l);
    int enabled = cfg_bool(l, fi, "enabled", 1);

    const char *ap = cfg_str(l, fi, "access_path");
    if (ap) snprintf(g_log_file.access_path, sizeof(g_log_file.access_path), "%s", ap);
    const char *ep = cfg_str(l, fi, "error_path");
    if (ep) snprintf(g_log_file.error_path, sizeof(g_log_file.error_path), "%s", ep);

    lua_getfield(l, fi, "access");
    if (lua_isboolean(l, -1)) g_log_file.access_on = lua_toboolean(l, -1) ? 1 : 0;
    else if (lua_isnumber(l, -1)) g_log_file.access_on = lua_tointeger(l, -1) != 0;
    else g_log_file.access_on = g_log_file.access_path[0] ? 1 : 0;
    lua_pop(l, 1);

    lua_getfield(l, fi, "error");
    if (lua_isboolean(l, -1)) g_log_file.error_on = lua_toboolean(l, -1) ? 1 : 0;
    else if (lua_isnumber(l, -1)) g_log_file.error_on = lua_tointeger(l, -1) != 0;
    else g_log_file.error_on = g_log_file.error_path[0] ? 1 : 0;
    lua_pop(l, 1);

    const char *flv = cfg_str(l, fi, "level");
    if (flv) g_log_file.level = log_level_num(flv);

    parse_log_file_keys(l, fi, &g_log_file);
    g_log_file.enabled = enabled ? 1 : 0;

    if (g_log_file.access_on && !g_log_file.access_path[0])
      die("log.file.access_path required when log.file.access = true");
    if (g_log_file.error_on && !g_log_file.error_path[0])
      die("log.file.error_path required when log.file.error = true");

    const char *legacy_a = cfg_str(l, li, "access");
    const char *legacy_e = cfg_str(l, li, "error");
    if (legacy_a || legacy_e) {
      log_error(LOG_WARN, "log: flat access/error fields are deprecated; use log.file.*");
    }
    lua_pop(l, 1);
  } else {
    lua_pop(l, 1);
    /* 兼容旧平铺写法：log.access / log.error 是路径 */
    const char *a = cfg_str(l, li, "access");
    const char *e = cfg_str(l, li, "error");
    if (a || e) {
      if (a) snprintf(g_log_file.access_path, sizeof(g_log_file.access_path), "%s", a);
      if (e) snprintf(g_log_file.error_path, sizeof(g_log_file.error_path), "%s", e);
      g_log_file.access_on = a ? 1 : 0;
      g_log_file.error_on = e ? 1 : 0;
      g_log_file.enabled = 1;
      parse_log_file_keys(l, li, &g_log_file);
    } else {
      g_log_file.enabled = 0;
    }
  }

  /* ---------- otlp ---------- */
  lua_getfield(l, li, "otlp");
  if (lua_istable(l, -1)) {
    int oi = lua_gettop(l);
    g_log_otlp.enabled = cfg_bool(l, oi, "enabled", 0);
    g_log_otlp.access_on = cfg_bool(l, oi, "access", 1);
    g_log_otlp.error_on = cfg_bool(l, oi, "error", 1);

    const char *olv = cfg_str(l, oi, "level");
    if (olv) g_log_otlp.level = log_level_num(olv);

    const char *ep = cfg_str(l, oi, "endpoint");
    if (ep) {
      char tmp[1024];
      log_otlp_normalize_url(ep, tmp, sizeof(tmp));
      snprintf(g_log_otlp.endpoint, sizeof(g_log_otlp.endpoint), "%s", tmp);
    }
    if (g_log_otlp.enabled && !g_log_otlp.endpoint[0])
      die("log.otlp.endpoint required when log.otlp.enabled = true");

    const char *ca = cfg_str(l, oi, "ca");
    if (ca) snprintf(g_log_otlp.ca, sizeof(g_log_otlp.ca), "%s", ca);
    g_log_otlp.verify = cfg_bool(l, oi, "verify", 1);

    const char *sn = cfg_str(l, oi, "service_name");
    if (sn) snprintf(g_log_otlp.service_name, sizeof(g_log_otlp.service_name), "%s", sn);

    lua_getfield(l, oi, "headers");
    if (lua_istable(l, -1)) {
      lua_pushnil(l);
      while (lua_next(l, -2)) {
        if (lua_type(l, -2) == LUA_TSTRING && lua_isstring(l, -1) &&
            g_log_otlp.nheaders < (int)(sizeof(g_log_otlp.headers) / sizeof(g_log_otlp.headers[0]))) {
          name_value_t *h = &g_log_otlp.headers[g_log_otlp.nheaders];
          snprintf(h->name, sizeof(h->name), "%s", lua_tostring(l, -2));
          snprintf(h->value, sizeof(h->value), "%s", lua_tostring(l, -1));
          g_log_otlp.nheaders++;
        }
        lua_pop(l, 1);
      }
    }
    lua_pop(l, 1);

    lua_getfield(l, oi, "resource");
    if (lua_istable(l, -1)) {
      lua_pushnil(l);
      while (lua_next(l, -2)) {
        if (lua_type(l, -2) == LUA_TSTRING && lua_isstring(l, -1) &&
            g_log_otlp.nresource < (int)(sizeof(g_log_otlp.resource) / sizeof(g_log_otlp.resource[0]))) {
          name_value_t *r = &g_log_otlp.resource[g_log_otlp.nresource];
          snprintf(r->name, sizeof(r->name), "%s", lua_tostring(l, -2));
          snprintf(r->value, sizeof(r->value), "%s", lua_tostring(l, -1));
          g_log_otlp.nresource++;
        }
        lua_pop(l, 1);
      }
    }
    lua_pop(l, 1);

    long long v = cfg_ll(l, oi, "batch_max_bytes", (long long)g_log_otlp.batch_max_bytes);
    if (v > 0) g_log_otlp.batch_max_bytes = (size_t)v;
    if (g_log_otlp.batch_max_bytes < 1024) die("log.otlp.batch_max_bytes too small");

    v = cfg_ll(l, oi, "batch_max_records", g_log_otlp.batch_max_records);
    if (v > 0) g_log_otlp.batch_max_records = (int)v;
    if (g_log_otlp.batch_max_records < 1 || g_log_otlp.batch_max_records > 100000)
      die("log.otlp.batch_max_records out of range");

    lua_getfield(l, oi, "flush_interval");
    if (lua_isnumber(l, -1)) {
      double sec = lua_tonumber(l, -1);
      int ms = (int)(sec * 1000);
      if (ms < 10) ms = 10;
      if (ms > 3600000) ms = 3600000;
      g_log_otlp.flush_ms = ms;
    }
    lua_pop(l, 1);

    v = cfg_ll(l, oi, "queue_max_bytes", (long long)g_log_otlp.queue_max_bytes);
    if (v > 0) g_log_otlp.queue_max_bytes = (size_t)v;
    if (g_log_otlp.queue_max_bytes < g_log_otlp.batch_max_bytes)
      die("log.otlp.queue_max_bytes must be >= batch_max_bytes");

    lua_getfield(l, oi, "timeout");
    if (lua_isnumber(l, -1)) {
      double sec = lua_tonumber(l, -1);
      int ms = (int)(sec * 1000);
      if (ms < 1000) ms = 1000;
      if (ms > 60000) ms = 60000;
      g_log_otlp.timeout_ms = ms;
    }
    lua_pop(l, 1);

    v = cfg_ll(l, oi, "max_retries", g_log_otlp.max_retries);
    if (v < 0) v = 0;
    if (v > 10) v = 10;
    g_log_otlp.max_retries = (int)v;

    lua_pop(l, 1); /* otlp */
  } else {
    lua_pop(l, 1);
  }

  /* ---------- syslog ---------- */
  lua_getfield(l, li, "syslog");
  if (lua_istable(l, -1)) {
    int si = lua_gettop(l);
    g_log_syslog.enabled = cfg_bool(l, si, "enabled", 0);
    g_log_syslog.access_on = cfg_bool(l, si, "access", 1);
    g_log_syslog.error_on = cfg_bool(l, si, "error", 1);

    const char *slv = cfg_str(l, si, "level");
    if (slv) g_log_syslog.level = log_level_num(slv);

    const char *tr = cfg_str(l, si, "transport");
    if (tr) {
      if (strcasecmp(tr, "udp") == 0) g_log_syslog.transport = 0;
      else if (strcasecmp(tr, "tcp") == 0) g_log_syslog.transport = 1;
      else if (strcasecmp(tr, "tls") == 0) g_log_syslog.transport = 2;
      else if (strcasecmp(tr, "unix") == 0) g_log_syslog.transport = 3;
      else die("log.syslog.transport must be udp, tcp, tls or unix");
    }

    const char *host = cfg_str(l, si, "host");
    if (host) snprintf(g_log_syslog.host, sizeof(g_log_syslog.host), "%s", host);

    long long port = cfg_ll(l, si, "port", g_log_syslog.port);
    if (port > 0 && port <= 65535) g_log_syslog.port = (int)port;
    else if (port != 0) die("log.syslog.port out of range");

    const char *path = cfg_str(l, si, "path");
    if (path) snprintf(g_log_syslog.path, sizeof(g_log_syslog.path), "%s", path);

    const char *fmt = cfg_str(l, si, "format");
    if (fmt) {
      if (strcasecmp(fmt, "rfc5424") == 0 || strcmp(fmt, "5424") == 0) g_log_syslog.format = 0;
      else if (strcasecmp(fmt, "rfc3164") == 0 || strcmp(fmt, "3164") == 0) g_log_syslog.format = 1;
      else die("log.syslog.format must be rfc5424 or rfc3164");
    }

    lua_getfield(l, si, "facility");
    if (lua_isnumber(l, -1)) {
      int f = (int)lua_tointeger(l, -1);
      if (f < 0 || f > 23) die("log.syslog.facility out of range");
      g_log_syslog.facility = f;
    } else if (lua_isstring(l, -1)) {
      g_log_syslog.facility = log_facility_num(lua_tostring(l, -1));
    }
    lua_pop(l, 1);

    const char *tag = cfg_str(l, si, "tag");
    if (tag) snprintf(g_log_syslog.tag, sizeof(g_log_syslog.tag), "%s", tag);

    long long q = cfg_ll(l, si, "queue_max_bytes", (long long)g_log_syslog.queue_max_bytes);
    if (q > 0) g_log_syslog.queue_max_bytes = (size_t)q;
    if (g_log_syslog.queue_max_bytes < 4096) die("log.syslog.queue_max_bytes too small");

    lua_getfield(l, si, "reconnect_interval");
    if (lua_isnumber(l, -1)) {
      double sec = lua_tonumber(l, -1);
      int ms = (int)(sec * 1000);
      if (ms < 100) ms = 100;
      if (ms > 60000) ms = 60000;
      g_log_syslog.reconnect_ms = ms;
    }
    lua_pop(l, 1);

    const char *ca = cfg_str(l, si, "ca");
    if (ca) snprintf(g_log_syslog.ca, sizeof(g_log_syslog.ca), "%s", ca);
    g_log_syslog.verify = cfg_bool(l, si, "verify", 1);

    if (g_log_syslog.enabled) {
      if (g_log_syslog.transport == 3) {
        if (!g_log_syslog.path[0]) die("log.syslog.path required for unix transport");
      } else {
        if (!g_log_syslog.host[0]) die("log.syslog.host required");
        if (g_log_syslog.port <= 0) die("log.syslog.port required");
      }
      if (g_log_syslog.transport == 2 && g_log_syslog.verify) {
        const char *caf = g_log_syslog.ca[0] ? g_log_syslog.ca
                                            : "/etc/ssl/certs/ca-certificates.crt";
        if (access(caf, R_OK) != 0) die("log.syslog.ca not readable: %s", caf);
      }
    }
    lua_pop(l, 1); /* syslog */
  } else {
    lua_pop(l, 1);
  }

  lua_pop(l, 1); /* log */
}

/* 最终校验：旧 table 路径与 FFI 路径共用；FFI 写入不经过 parse_log 的校验 */
static void validate_log_config(void)
{
  if (g_log_file.enabled) {
    if (g_log_file.access_on && !g_log_file.access_path[0])
      die("log.file.access_path required when log.file.access = true");
    if (g_log_file.error_on && !g_log_file.error_path[0])
      die("log.file.error_path required when log.file.error = true");
    if (g_log_file.max_bytes < 4096) die("log.file.max_buffer too small");
  }
  if (g_log_otlp.enabled) {
    if (!g_log_otlp.endpoint[0])
      die("log.otlp.endpoint required when log.otlp.enabled = true");
    if (g_log_otlp.batch_max_bytes < 1024) die("log.otlp.batch_max_bytes too small");
    if (g_log_otlp.batch_max_records < 1) die("log.otlp.batch_max_records out of range");
    if (g_log_otlp.queue_max_bytes < g_log_otlp.batch_max_bytes)
      die("log.otlp.queue_max_bytes must be >= batch_max_bytes");
  }
  if (g_log_syslog.enabled) {
    if (g_log_syslog.transport == 3) {
      if (!g_log_syslog.path[0]) die("log.syslog.path required for unix transport");
    } else {
      if (!g_log_syslog.host[0]) die("log.syslog.host required");
      if (g_log_syslog.port <= 0) die("log.syslog.port required");
    }
    if (g_log_syslog.transport == 2 && g_log_syslog.verify) {
      const char *caf = g_log_syslog.ca[0] ? g_log_syslog.ca
                                          : "/etc/ssl/certs/ca-certificates.crt";
      if (access(caf, R_OK) != 0) die("log.syslog.ca not readable: %s", caf);
    }
  }
}

/* 启动时把配置恢复到内置默认值（main 里 env 覆盖前调用） */
static void config_defaults_init(void)
{
  g_config = k_config_defaults;
  g_tcp = k_tcp_defaults;
  g_revocation = k_revocation_defaults;
  max_body_stream = g_env_max_body ? g_env_max_body : MAX_BODY_STREAM_DEFAULT;
}

/* reload 前把可解析的全局状态清回默认值，再让 parse_* 写入新值 */
static void config_reset_for_reload(void)
{
  g_config.log = k_config_defaults.log;
  g_tcp = k_tcp_defaults;

  g_max_head_size = MAX_HEAD_SIZE;
  g_auto_buffer_body = AUTO_BUFFER_BODY;
  g_read_high_water = READ_HIGH_WATER;
  g_write_high_water = WRITE_HIGH_WATER;
  g_write_low_water = WRITE_LOW_WATER;
  g_write_hard_limit = WRITE_HARD_LIMIT;
  g_idle_timeout_ms = IDLE_TIMEOUT_MS;
  g_handshake_timeout_ms = 10 * 1000;
  g_max_connections = 1024;
  g_shutdown_timeout_ms = 10000;
  max_body_stream = g_env_max_body ? g_env_max_body : MAX_BODY_STREAM_DEFAULT;

  g_tls_cert_path[0] = 0;
  g_tls_key_path[0] = 0;
  g_tls_ca_path[0] = 0;
  g_tls_client_auth = 0;
  g_tls_min13 = 0;
  g_tls_alpn_count = 0;
  memset(g_tls_alpn_buf, 0, sizeof(g_tls_alpn_buf));
  memset(g_tls_alpn, 0, sizeof(g_tls_alpn));
  for (size_t i = 0; i < MAX_SNI_CERTS; i++) {
    g_sni_names[i][0] = 0;
    g_sni_cert_paths[i][0] = 0;
    g_sni_key_paths[i][0] = 0;
    g_sni_ca_paths[i][0] = 0;
    g_sni_client_auth[i] = -1;
  }
  g_sni_count = 0;
  g_tls_check_interval_ms = 10000;
  g_tls_enabled = 0;
  g_tls_gen = NULL;

  g_revocation = k_revocation_defaults;
  g_listeners = NULL;
  g_listener_count = 0;
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

/* bind 与 listen 分开：多 worker 启动时要等所有 worker 配置加载完再一起 accept */
static void start_listeners(void)
{
  for (size_t i = 0; i < g_listener_count; i++) {
    listener_t *l = &g_listeners[i];
    int r = uv_listen((uv_stream_t *)&l->handle, g_tcp.backlog, on_connection);
    if (r != 0) die("listen %s:%d failed: %s", l->host, l->port, uv_strerror(r));
  }
}

/* ---------- 初始化 ---------- */

static void init_lua(const char *path, int cli_port, int check_mode)
{
  snprintf(g_config_path, sizeof(g_config_path), "%s", path);
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

  /* 配置库：导出配置结构体地址 + ABI 表，并注入字节码 */
  lua_register(L, "__httpd_config_root", l_httpd_config_root);
  lua_register(L, "__httpd_config_abi", l_httpd_config_abi);

  /* 先注入 cdef 字符串，再注入配置库（库执行时读取 __httpd_config_cdef） */
  inject_bytecode(L, luaJIT_BC_config_cdef, luaJIT_BC_config_cdef_len,
                  "=config_cdef", "__httpd_config_cdef");
  inject_bytecode(L, luaJIT_BC_httpd_config, luaJIT_BC_httpd_config_len,
                  "=httpd_config", "httpd_config");
  lua_pushnil(L);
  lua_setglobal(L, "__httpd_config_cdef");

  int base = lua_gettop(L);
  if (luaL_dofile(L, path) != 0) {
    fprintf(stderr, "failed to load %s: %s\n", path, lua_tostring(L, -1));
    exit(1);
  }
  int cfg;
  if (lua_gettop(L) > base && lua_istable(L, -1)) {
    cfg = lua_gettop(L);
  } else {
    /* 允许配置文件只写全局 config = {...} 而不 return */
    if (lua_gettop(L) > base) lua_pop(L, lua_gettop(L) - base);
    lua_getglobal(L, "config");
    if (!lua_istable(L, -1)) {
      fprintf(stderr, "%s must return a table or define global config\n", path);
      exit(1);
    }
    cfg = lua_gettop(L);
  }

  /* 业务可读全局 config（uploader URI、路由等） */
  lua_pushvalue(L, cfg);
  lua_setglobal(L, "config");

  /* 注入的配置库隐式读取 table 里的 log 段（FFI 写 C 结构） */
  lua_getglobal(L, "httpd_config");
  if (lua_istable(L, -1)) {
    lua_getfield(L, -1, "load");
    if (lua_isfunction(L, -1)) {
      lua_pushvalue(L, cfg);
      if (lua_pcall(L, 1, 0, 0) != 0) {
        fprintf(stderr, "httpd_config.load failed: %s\n", lua_tostring(L, -1));
        exit(1);
      }
      lua_pop(L, 1); /* httpd_config table */
    } else {
      lua_pop(L, 2);
    }
  } else {
    lua_pop(L, 1);
  }

  int ffi_used = 0;
  lua_getglobal(L, "__httpd_config_used");
  if (lua_isboolean(L, -1)) ffi_used = lua_toboolean(L, -1);
  lua_pop(L, 1);

  parse_revocation(L, cfg);
  if (!ffi_used) parse_log(L, cfg);
  validate_log_config();

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
    if (check_mode) {
      /* --check 不执行 app.lua（避免副作用），只检查文件可读 */
      if (access(app_path, R_OK) != 0) {
        fprintf(stderr, "config error: app file not readable: %s\n", app_path);
        exit(1);
      }
    } else {
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
    }
  } else {
    lua_pop(L, 1);
    lua_getfield(L, cfg, "handle");
    if (!lua_isfunction(L, -1)) {
      fprintf(stderr, "%s must define app = \"...\" or a handle function\n", path);
      exit(1);
    }
    if (check_mode) {
      lua_pop(L, 1);
    } else {
      app_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
  }

  lua_pop(L, 1); /* config table */
}

/* ---------- 配置检查（--check）与重载（SIGHUP） ---------- */

static int check_log_path(const char *path)
{
  if (!path || !path[0]) return 0;
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) {
    fprintf(stderr, "config error: cannot open log file %s: %s\n",
            path, strerror(errno));
    return -1;
  }
  close(fd);
  return 0;
}

static int check_listen_duplicates(void)
{
  for (size_t i = 0; i < g_listener_count; i++) {
    for (size_t j = i + 1; j < g_listener_count; j++) {
      if (g_listeners[i].port == g_listeners[j].port &&
          strcmp(g_listeners[i].host, g_listeners[j].host) == 0) {
        fprintf(stderr, "config error: duplicate listen %s:%d\n",
                g_listeners[i].host, g_listeners[i].port);
        return -1;
      }
    }
  }
  return 0;
}

static int config_check_extra(void)
{
  if (g_log_file.enabled) {
    if (g_log_file.access_on && check_log_path(g_log_file.access_path) != 0) return -1;
    if (g_log_file.error_on && check_log_path(g_log_file.error_path) != 0) return -1;
  }
  if (g_revocation.enabled && g_revocation.source_file[0] &&
      access(g_revocation.source_file, R_OK) != 0) {
    fprintf(stderr, "config error: revocation file not readable: %s\n",
            g_revocation.source_file);
    return -1;
  }
  return check_listen_duplicates();
}

typedef struct {
  httpd_config_t config;
  listener_t *listeners;
  size_t listener_count;
  tcp_opts_t tcp;
  size_t max_head_size, auto_buffer_body, read_high_water;
  size_t write_high_water, write_low_water, write_hard_limit;
  unsigned idle_timeout_ms, handshake_timeout_ms;
  size_t max_connections, max_body_stream;
  unsigned shutdown_timeout_ms;
  char tls_cert_path[512], tls_key_path[512], tls_ca_path[512];
  int tls_client_auth, tls_min13;
  char tls_alpn_buf[8][64];
  const char *tls_alpn[9];
  int tls_alpn_count;
  char sni_names[MAX_SNI_CERTS][128];
  char sni_cert_paths[MAX_SNI_CERTS][512];
  char sni_key_paths[MAX_SNI_CERTS][512];
  char sni_ca_paths[MAX_SNI_CERTS][512];
  int sni_client_auth[MAX_SNI_CERTS];
  size_t sni_count;
  int tls_check_interval_ms;
  int tls_enabled;
  tls_gen_t *tls_gen;
  revocation_cfg_t revocation;
  int config_ref;
  int used_before;
} reload_backup_t;

static void reload_save(reload_backup_t *b)
{
  memset(b, 0, sizeof(*b));
  b->config = g_config;
  b->listeners = g_listeners;
  b->listener_count = g_listener_count;
  b->tcp = g_tcp;
  b->max_head_size = g_max_head_size;
  b->auto_buffer_body = g_auto_buffer_body;
  b->read_high_water = g_read_high_water;
  b->write_high_water = g_write_high_water;
  b->write_low_water = g_write_low_water;
  b->write_hard_limit = g_write_hard_limit;
  b->idle_timeout_ms = g_idle_timeout_ms;
  b->handshake_timeout_ms = g_handshake_timeout_ms;
  b->max_connections = g_max_connections;
  b->max_body_stream = max_body_stream;
  b->shutdown_timeout_ms = g_shutdown_timeout_ms;
  snprintf(b->tls_cert_path, sizeof(b->tls_cert_path), "%s", g_tls_cert_path);
  snprintf(b->tls_key_path, sizeof(b->tls_key_path), "%s", g_tls_key_path);
  snprintf(b->tls_ca_path, sizeof(b->tls_ca_path), "%s", g_tls_ca_path);
  b->tls_client_auth = g_tls_client_auth;
  b->tls_min13 = g_tls_min13;
  memcpy(b->tls_alpn_buf, g_tls_alpn_buf, sizeof(b->tls_alpn_buf));
  memcpy(b->tls_alpn, g_tls_alpn, sizeof(b->tls_alpn));
  b->tls_alpn_count = g_tls_alpn_count;
  memcpy(b->sni_names, g_sni_names, sizeof(b->sni_names));
  memcpy(b->sni_cert_paths, g_sni_cert_paths, sizeof(b->sni_cert_paths));
  memcpy(b->sni_key_paths, g_sni_key_paths, sizeof(b->sni_key_paths));
  memcpy(b->sni_ca_paths, g_sni_ca_paths, sizeof(b->sni_ca_paths));
  memcpy(b->sni_client_auth, g_sni_client_auth, sizeof(b->sni_client_auth));
  b->sni_count = g_sni_count;
  b->tls_check_interval_ms = g_tls_check_interval_ms;
  b->tls_enabled = g_tls_enabled;
  b->tls_gen = g_tls_gen;
  b->revocation = g_revocation;

  lua_getglobal(L, "__httpd_config_used");
  b->used_before = lua_isboolean(L, -1) && lua_toboolean(L, -1);
  lua_pop(L, 1);

  lua_getglobal(L, "config");
  b->config_ref = luaL_ref(L, LUA_REGISTRYINDEX);
}

static void reload_restore(reload_backup_t *b)
{
  g_config = b->config;
  g_listeners = b->listeners;
  g_listener_count = b->listener_count;
  g_tcp = b->tcp;
  g_max_head_size = b->max_head_size;
  g_auto_buffer_body = b->auto_buffer_body;
  g_read_high_water = b->read_high_water;
  g_write_high_water = b->write_high_water;
  g_write_low_water = b->write_low_water;
  g_write_hard_limit = b->write_hard_limit;
  g_idle_timeout_ms = b->idle_timeout_ms;
  g_handshake_timeout_ms = b->handshake_timeout_ms;
  g_max_connections = b->max_connections;
  max_body_stream = b->max_body_stream;
  g_shutdown_timeout_ms = b->shutdown_timeout_ms;
  snprintf(g_tls_cert_path, sizeof(g_tls_cert_path), "%s", b->tls_cert_path);
  snprintf(g_tls_key_path, sizeof(g_tls_key_path), "%s", b->tls_key_path);
  snprintf(g_tls_ca_path, sizeof(g_tls_ca_path), "%s", b->tls_ca_path);
  g_tls_client_auth = b->tls_client_auth;
  g_tls_min13 = b->tls_min13;
  memcpy(g_tls_alpn_buf, b->tls_alpn_buf, sizeof(g_tls_alpn_buf));
  memcpy(g_tls_alpn, b->tls_alpn, sizeof(g_tls_alpn));
  g_tls_alpn_count = b->tls_alpn_count;
  memcpy(g_sni_names, b->sni_names, sizeof(g_sni_names));
  memcpy(g_sni_cert_paths, b->sni_cert_paths, sizeof(g_sni_cert_paths));
  memcpy(g_sni_key_paths, b->sni_key_paths, sizeof(g_sni_key_paths));
  memcpy(g_sni_ca_paths, b->sni_ca_paths, sizeof(g_sni_ca_paths));
  memcpy(g_sni_client_auth, b->sni_client_auth, sizeof(g_sni_client_auth));
  g_sni_count = b->sni_count;
  g_tls_check_interval_ms = b->tls_check_interval_ms;
  g_tls_enabled = b->tls_enabled;
  g_tls_gen = b->tls_gen;
  g_revocation = b->revocation;

  if (b->config_ref != LUA_NOREF && b->config_ref != LUA_REFNIL) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, b->config_ref);
    lua_setglobal(L, "config");
    luaL_unref(L, LUA_REGISTRYINDEX, b->config_ref);
  } else {
    lua_pushnil(L);
    lua_setglobal(L, "config");
  }
  b->config_ref = LUA_NOREF;

  if (b->used_before) {
    lua_pushboolean(L, 1);
  } else {
    lua_pushnil(L);
  }
  lua_setglobal(L, "__httpd_config_used");
}

static int listeners_equal(listener_t *a, size_t na, listener_t *b, size_t nb)
{
  if (na != nb) return 0;
  for (size_t i = 0; i < na; i++) {
    if (strcmp(a[i].host, b[i].host) != 0) return 0;
    if (a[i].tls != b[i].tls) return 0;
    if (!(g_cli_port > 0 && i == 0) && a[i].port != b[i].port) return 0;
  }
  return 1;
}

/* 在 reload 中重新加载配置：失败返回 -1（Lua/库错误），die() 用 longjmp 返回 */
static int reload_load_config(void)
{
  int base = lua_gettop(L);
  if (luaL_dofile(L, g_config_path) != 0) {
    snprintf(g_cfg_err, sizeof(g_cfg_err), "%s", lua_tostring(L, -1));
    return -1;
  }

  int cfg;
  if (lua_gettop(L) > base && lua_istable(L, -1)) {
    cfg = lua_gettop(L);
  } else {
    if (lua_gettop(L) > base) lua_pop(L, lua_gettop(L) - base);
    lua_getglobal(L, "config");
    if (!lua_istable(L, -1)) {
      snprintf(g_cfg_err, sizeof(g_cfg_err),
               "config file must return a table or define global config");
      return -1;
    }
    cfg = lua_gettop(L);
  }

  lua_pushvalue(L, cfg);
  lua_setglobal(L, "config");

  lua_getglobal(L, "httpd_config");
  if (lua_istable(L, -1)) {
    lua_getfield(L, -1, "load");
    if (lua_isfunction(L, -1)) {
      lua_pushvalue(L, cfg);
      if (lua_pcall(L, 1, 0, 0) != 0) {
        snprintf(g_cfg_err, sizeof(g_cfg_err), "httpd_config.load: %s",
                 lua_tostring(L, -1));
        return -1;
      }
      lua_pop(L, 1);
    } else {
      lua_pop(L, 2);
    }
  } else {
    lua_pop(L, 1);
  }

  int ffi_used = 0;
  lua_getglobal(L, "__httpd_config_used");
  if (lua_isboolean(L, -1)) ffi_used = lua_toboolean(L, -1);
  lua_pop(L, 1);

  parse_revocation(L, cfg);
  if (!ffi_used) parse_log(L, cfg);
  validate_log_config();

  lua_getfield(L, cfg, "server");
  if (lua_istable(L, -1)) {
    parse_server(L, lua_gettop(L), g_cli_port);
    lua_pop(L, 1);
  } else {
    lua_pop(L, 1);
    add_listener("0.0.0.0", g_cli_port > 0 ? g_cli_port : 8080, 0);
  }
  return 0;
}

static void log_reload_apply(const httpd_log_cfg_t *newc)
{
  if (newc->file.enabled) {
    if (newc->file.access_on && g_access_log.enabled) {
      log_sink_update(&g_access_log, newc->file.access_path, newc->file.max_bytes,
                      newc->file.flush_ms, newc->file.rotate_ms,
                      newc->file.rotate_size, newc->file.rotate_keep);
    }
    if (newc->file.error_on && g_error_log.enabled) {
      log_sink_update(&g_error_log, newc->file.error_path, newc->file.max_bytes,
                      newc->file.flush_ms, newc->file.rotate_ms,
                      newc->file.rotate_size, newc->file.rotate_keep);
    }
  }
  if (newc->syslog.enabled) {
    uv_mutex_lock(&g_syslog.mu);
    g_syslog.reload = 1;
    uv_cond_signal(&g_syslog.cond);
    uv_mutex_unlock(&g_syslog.mu);
  }
}

static void revocation_reconfigure(void)
{
  uv_timer_stop(&g_revocation_timer);
  if (g_revocation.enabled && g_revocation.interval_ms > 0) {
    uv_timer_start(&g_revocation_timer, revocation_timer_cb,
                   (uint64_t)g_revocation.interval_ms,
                   (uint64_t)g_revocation.interval_ms);
  }
  if (g_revocation.enabled) {
    revocation_timer_cb(&g_revocation_timer);
  }
}

static void tls_check_reconfigure(void)
{
  uv_timer_stop(&g_tls_check_timer);
  if (g_tls_enabled && g_tls_check_interval_ms > 0) {
    uv_timer_start(&g_tls_check_timer, tls_check_timer_cb,
                   (uint64_t)g_tls_check_interval_ms,
                   (uint64_t)g_tls_check_interval_ms);
  }
}

static int g_reloading;

static void reload_config(void)
{
  if (g_reloading) {
    log_error(LOG_WARN, "reload: already in progress");
    return;
  }
  g_reloading = 1;

  reload_backup_t b;
  reload_save(&b);
  int base = lua_gettop(L);

  config_reset_for_reload();

  jmp_buf jb;
  int ok = 0;
  g_cfg_jmp = &jb;
  if (setjmp(jb) == 0) {
    if (reload_load_config() == 0) ok = 1;
  } else {
    ok = 0;
  }
  g_cfg_jmp = NULL;

  if (ok && !listeners_equal(g_listeners, g_listener_count, b.listeners, b.listener_count)) {
    snprintf(g_cfg_err, sizeof(g_cfg_err), "listen changes require restart");
    ok = 0;
  }

  if (ok) {
    const httpd_log_cfg_t *oldc = &b.config.log;
    const httpd_log_cfg_t *newc = &g_config.log;
    if (oldc->file.enabled != newc->file.enabled ||
        oldc->file.access_on != newc->file.access_on ||
        oldc->file.error_on != newc->file.error_on ||
        oldc->otlp.enabled != newc->otlp.enabled ||
        oldc->syslog.enabled != newc->syslog.enabled) {
      snprintf(g_cfg_err, sizeof(g_cfg_err),
               "log channel enable/disable requires restart");
      ok = 0;
    }
  }

  if (!ok) {
    if (g_listeners && g_listeners != b.listeners) free(g_listeners);
    if (g_tls_gen && g_tls_gen != b.tls_gen) tls_gen_unref(g_tls_gen);
    lua_settop(L, base);
    reload_restore(&b);
    log_error(LOG_ERROR, "reload failed: %s",
              g_cfg_err[0] ? g_cfg_err : "unknown error");
    g_reloading = 0;
    return;
  }

  /* 切换（不再执行可能失败的操作） */
  free(g_listeners);
  g_listeners = b.listeners;
  g_listener_count = b.listener_count;

  if (b.tls_gen) tls_gen_unref(b.tls_gen);

  log_reload_apply(&g_config.log);
  revocation_reconfigure();
  tls_check_reconfigure();
  if (g_env_max_body) max_body_stream = g_env_max_body;

  lua_settop(L, base);
  if (b.config_ref != LUA_NOREF && b.config_ref != LUA_REFNIL) {
    luaL_unref(L, LUA_REGISTRYINDEX, b.config_ref);
  }

  log_error(LOG_INFO, "reload: configuration applied (%s)", g_config_path);
  g_reloading = 0;
}

/* ---------- 多 worker（单进程、SO_REUSEPORT、每 worker 一个 loop + 一个 VM） ---------- */

/* 只读取 server.workers，不触发配置库/parse_*；配置文件需是纯 table（无副作用）。
 * 快路径：文件里根本没有 workers 字样时直接返回 1，避免普通配置被执行两次。 */
static int detect_workers(const char *path)
{
  FILE *f = fopen(path, "r");
  if (!f) return 1;
  char buf[256 * 1024];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = 0;
  if (!strstr(buf, "workers")) return 1;

  lua_State *t = luaL_newstate();
  if (!t) return 1;
  luaL_openlibs(t);
  int workers = 1;
  if (luaL_dofile(t, path) == 0 && lua_istable(t, -1)) {
    lua_getfield(t, -1, "server");
    if (lua_istable(t, -1)) {
      lua_getfield(t, -1, "workers");
      if (lua_isnumber(t, -1)) {
        workers = (int)lua_tointeger(t, -1);
      } else if (lua_isstring(t, -1) && strcmp(lua_tostring(t, -1), "auto") == 0) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        workers = n > 0 ? (int)n : 1;
      }
      lua_pop(t, 1);
    }
    lua_pop(t, 1);
  }
  lua_close(t);
  if (workers < 1) workers = 1;
  if (workers > 256) workers = 256;
  return workers;
}

/* worker 侧应用 reload：只动本 VM 的全局 config/app/TLS 代；全局标量由 control 发布 */
static int worker_reload_apply(worker_t *w)
{
  lua_State *l = L;
  int base = lua_gettop(l);
  int cfg = 0;
  int new_app = LUA_NOREF;
  tls_gen_t *ng = NULL;
  int ok = 0;

  httpd_config_t tmp;
  memcpy(&tmp, &g_config, sizeof(tmp));
  t_config = &tmp;

  if (luaL_dofile(l, g_config_path) != 0) goto done;
  if (lua_gettop(l) > base && lua_istable(l, -1)) {
    cfg = lua_gettop(l);
  } else {
    if (lua_gettop(l) > base) lua_pop(l, lua_gettop(l) - base);
    lua_getglobal(l, "config");
    if (!lua_istable(l, -1)) goto done;
    cfg = lua_gettop(l);
  }

  /* 配置库写线程局部副本，校验失败不影响全局 */
  lua_getglobal(l, "httpd_config");
  if (lua_istable(l, -1)) {
    lua_getfield(l, -1, "load");
    if (lua_isfunction(l, -1)) {
      lua_pushvalue(l, cfg);
      if (lua_pcall(l, 1, 0, 0) != 0) { lua_pop(l, 1); goto done; }
      lua_pop(l, 1);
    } else {
      lua_pop(l, 2);
    }
  } else {
    lua_pop(l, 1);
  }

  /* 新 app：路径或配置表里的 handle 函数 */
  lua_getfield(l, cfg, "app");
  if (lua_isstring(l, -1)) {
    const char *app_path = lua_tostring(l, -1);
    lua_pop(l, 1);
    if (luaL_dofile(l, app_path) != 0) goto done;
    if (!lua_istable(l, -1)) goto done;
    lua_getfield(l, -1, "handle");
    if (!lua_isfunction(l, -1)) goto done;
    new_app = luaL_ref(l, LUA_REGISTRYINDEX);
  } else {
    lua_pop(l, 1);
    lua_getfield(l, cfg, "handle");
    if (!lua_isfunction(l, -1)) goto done;
    new_app = luaL_ref(l, LUA_REGISTRYINDEX);
  }

  /* TLS 代：用 control 已发布的全局路径/SNI 配置重建 */
  if (g_tls_enabled) {
    ng = tls_gen_build(0);
    if (!ng) goto done;
  }

  /* 全部成功后再切换 */
  if (ng) {
    tls_gen_ref(ng);
    tls_gen_t *old = g_tls_gen;
    g_tls_gen = ng;
    if (old) tls_gen_unref(old);
  }
  {
    int old_app = app_ref;
    app_ref = new_app;
    new_app = LUA_NOREF;
    if (old_app != LUA_NOREF) luaL_unref(l, LUA_REGISTRYINDEX, old_app);
  }
  lua_pushvalue(l, cfg);
  lua_setglobal(l, "config");
  ok = 1;

done:
  if (new_app != LUA_NOREF) luaL_unref(l, LUA_REGISTRYINDEX, new_app);
  lua_settop(l, base);
  t_config = NULL;

  if (!ok) {
    log_error(LOG_ERROR, "reload: worker %d failed to apply", w->id);
    return -1;
  }

  /* TLS 检测/吊销表定时器按新 interval 重新起（各自 worker loop） */
  uv_timer_stop(&g_tls_check_timer);
  if (g_tls_enabled && g_tls_check_interval_ms > 0) {
    uv_timer_start(&g_tls_check_timer, tls_check_timer_cb,
                   (uint64_t)g_tls_check_interval_ms,
                   (uint64_t)g_tls_check_interval_ms);
  }
  if (w->id == 0) {
    uv_timer_stop(&g_revocation_timer);
    if (g_revocation.enabled && g_revocation.interval_ms > 0) {
      uv_timer_start(&g_revocation_timer, revocation_timer_cb,
                     (uint64_t)g_revocation.interval_ms,
                     (uint64_t)g_revocation.interval_ms);
    }
    if (g_revocation.enabled) revocation_timer_cb(&g_revocation_timer);
  }
  log_error(LOG_INFO, "reload: worker %d applied", w->id);
  return 0;
}

static void worker_ctrl_cb(uv_async_t *h)
{
  worker_t *w = (worker_t *)h->data;
  if (g_ctrl_shutdown) {
    if (g_ctrl_force) force_shutdown();
    else begin_graceful_shutdown();
    return;
  }
  unsigned seq = __atomic_load_n(&g_ctrl_reload_seq, __ATOMIC_ACQUIRE);
  if (seq != w->reload_seen) {
    w->reload_seen = seq;
    worker_reload_apply(w);
  }
}

static void worker_thread_main(void *arg)
{
  worker_t *w = (worker_t *)arg;
  g_current_worker_id = w->id;
  loop = &w->loop;
  if (uv_loop_init(loop) != 0) {
    fprintf(stderr, "worker %d: uv_loop_init failed\n", w->id);
    exit(1);
  }
  if (uv_async_init(loop, &w->ctrl, worker_ctrl_cb) != 0) {
    fprintf(stderr, "worker %d: uv_async_init failed\n", w->id);
    exit(1);
  }
  w->ctrl.data = w;

  /* 启动阶段串行化：所有 worker 会写同一份 g_config，但都在 accept 之前完成。
   * 运行期配置只读；reload 由 control 校验后广播，worker 只重载本 VM 的 config/app/TLS。 */
  /* init_lua 会把 path 写回 g_config_path；这里先拷贝，避免自覆盖 */
  char cfg_path[512];
  snprintf(cfg_path, sizeof(cfg_path), "%s", g_config_path);

  uv_mutex_lock(&g_cfg_init_mutex);
  config_defaults_init();
  init_lua(cfg_path, g_cli_port, 0);
  tls_snapshot_init();
  revocation_init();
  create_listeners();          /* 只 bind，不 listen */
  /* 最后一个完成配置的 worker 记录 listen 快照并启动全局日志管道 */
  if (__atomic_add_fetch(&g_log_init_done, 1, __ATOMIC_ACQ_REL) == g_worker_count) {
    listen_snapshot_capture();
    log_pipeline_start();
  }
  uv_mutex_unlock(&g_cfg_init_mutex);

  /* 所有 worker 配置/证书/日志就绪后，同时开始 accept */
  uv_barrier_wait(&g_init_barrier);
  start_listeners();

  uv_timer_init(loop, &g_shutdown_timer);
  uv_timer_init(loop, &g_tls_check_timer);
  if (g_tls_enabled && g_tls_check_interval_ms > 0) {
    uv_timer_start(&g_tls_check_timer, tls_check_timer_cb,
                   (uint64_t)g_tls_check_interval_ms,
                   (uint64_t)g_tls_check_interval_ms);
  }
  /* 吊销表是进程级共享表，只由 worker 0 的 loop 负责定时刷新 */
  if (w->id == 0) {
    uv_timer_init(loop, &g_revocation_timer);
    if (g_revocation.enabled && g_revocation.interval_ms > 0) {
      uv_timer_start(&g_revocation_timer, revocation_timer_cb,
                     (uint64_t)g_revocation.interval_ms,
                     (uint64_t)g_revocation.interval_ms);
    }
  }

  if (w->id == 0) {
    for (size_t i = 0; i < g_listener_count; i++) {
      listener_t *l = &g_listeners[i];
      log_error(LOG_INFO, "listener %s:%d (%s)",
                l->host, l->port, l->tls ? "https" : "http");
    }
    if (g_tls_enabled)
      log_error(LOG_INFO, "tls: %zu sni pair(s), periodic check every %dms",
                g_sni_count, g_tls_check_interval_ms);
    if (g_revocation.enabled) {
      revoked_store_t *rs = __atomic_load_n(&g_revoked, __ATOMIC_ACQUIRE);
      log_error(LOG_INFO, "revocation: enabled, %zu entries, periodic every %dms, provider=%s",
                rs ? rs->count : 0, g_revocation.interval_ms,
                g_revocation.provider_type);
    }
    log_error(LOG_INFO,
              "workers=%zu max_body=%zu idle_timeout=%us shutdown_timeout=%ums "
              "tcp{nodelay=%d keepalive=%d backlog=%d reuse_port=%d}",
              g_worker_count, max_body_stream, g_idle_timeout_ms / 1000,
              g_shutdown_timeout_ms, g_tcp.nodelay, g_tcp.keepalive,
              g_tcp.backlog, g_tcp.reuse_port);
  }

  uv_run(loop, UV_RUN_DEFAULT);

  /* 日志管道是进程级的，由 control 在所有 worker 退出后统一 flush/关闭 */
  if (L) { lua_close(L); L = NULL; }

  /* loop/handle 内存随线程退出由进程回收；这里只标记完成并通知 control */
  __atomic_add_fetch(&g_workers_done, 1, __ATOMIC_RELEASE);
  uv_async_send(&g_ctrl_done_async);
}

static void on_worker_done(uv_async_t *h)
{
  (void)h;
  if (__atomic_load_n(&g_workers_done, __ATOMIC_ACQUIRE) >= g_worker_count)
    uv_stop(&g_ctrl_loop);
}

/* control 侧多 worker reload：校验 listen/log 开关/app，发布全局标量，worker 各自应用 */
static int multi_reload_config(void)
{
  if (g_reloading) {
    fprintf(stderr, "reload: already in progress\n");
    return -1;
  }
  g_reloading = 1;
  g_cfg_err[0] = 0;

  lua_State *saved_L = L;
  lua_State *t = luaL_newstate();
  if (!t) { g_reloading = 0; return -1; }
  luaL_openlibs(t);
  lua_register(t, "__httpd_config_root", l_httpd_config_root);
  lua_register(t, "__httpd_config_abi", l_httpd_config_abi);
  inject_bytecode(t, luaJIT_BC_config_cdef, luaJIT_BC_config_cdef_len,
                  "=config_cdef", "__httpd_config_cdef");
  inject_bytecode(t, luaJIT_BC_httpd_config, luaJIT_BC_httpd_config_len,
                  "=httpd_config", "httpd_config");
  lua_pushnil(t);
  lua_setglobal(t, "__httpd_config_cdef");
  L = t;

  reload_backup_t b;
  reload_save(&b);
  int base = lua_gettop(L);
  config_reset_for_reload();

  jmp_buf jb;
  int ok = 0;
  g_cfg_jmp = &jb;
  if (setjmp(jb) == 0) {
    if (reload_load_config() == 0) ok = 1;
  } else {
    ok = 0;
  }
  g_cfg_jmp = NULL;

  if (ok && !listen_snapshot_matches()) {
    snprintf(g_cfg_err, sizeof(g_cfg_err), "listen changes require restart");
    ok = 0;
  }

  if (ok) {
    const httpd_log_cfg_t *oldc = &b.config.log;
    const httpd_log_cfg_t *newc = &g_config.log;
    if (oldc->file.enabled != newc->file.enabled ||
        oldc->file.access_on != newc->file.access_on ||
        oldc->file.error_on != newc->file.error_on ||
        oldc->otlp.enabled != newc->otlp.enabled ||
        oldc->syslog.enabled != newc->syslog.enabled) {
      snprintf(g_cfg_err, sizeof(g_cfg_err),
               "log channel enable/disable requires restart");
      ok = 0;
    }
  }

  /* app 只做语法/存在性检查，不执行（真正加载在 worker 应用阶段） */
  if (ok) {
    lua_getglobal(L, "config");
    if (!lua_istable(L, -1)) {
      snprintf(g_cfg_err, sizeof(g_cfg_err), "config table missing");
      ok = 0;
    } else {
      lua_getfield(L, -1, "app");
      if (lua_isstring(L, -1)) {
        const char *app_path = lua_tostring(L, -1);
        if (access(app_path, R_OK) != 0) {
          snprintf(g_cfg_err, sizeof(g_cfg_err),
                   "app file not readable: %s", app_path);
          ok = 0;
        } else if (luaL_loadfile(L, app_path) != 0) {
          snprintf(g_cfg_err, sizeof(g_cfg_err), "app load: %s",
                   lua_tostring(L, -1));
          ok = 0;
        } else {
          lua_pop(L, 1);
        }
      } else {
        lua_pop(L, 1);
        lua_getfield(L, -1, "handle");
        if (!lua_isfunction(L, -1)) {
          snprintf(g_cfg_err, sizeof(g_cfg_err), "app handle missing");
          ok = 0;
        }
        lua_pop(L, 1);
      }
      lua_pop(L, 1);
    }
  }

  if (!ok) {
    if (g_listeners && g_listeners != b.listeners) free(g_listeners);
    if (g_tls_gen && g_tls_gen != b.tls_gen) tls_gen_unref(g_tls_gen);
    lua_settop(L, base);
    reload_restore(&b);
    log_error(LOG_ERROR, "reload failed: %s",
              g_cfg_err[0] ? g_cfg_err : "unknown error");
    L = saved_L;
    lua_close(t);
    g_reloading = 0;
    return -1;
  }

  /* 成功：control 侧只用于校验的 listeners/TLS 代释放掉，worker 各自持自己的 */
  free(g_listeners);
  g_listeners = NULL;
  g_listener_count = 0;
  if (g_tls_gen) { tls_gen_unref(g_tls_gen); g_tls_gen = NULL; }
  if (b.tls_gen) tls_gen_unref(b.tls_gen);
  lua_settop(L, base);
  if (b.config_ref != LUA_NOREF && b.config_ref != LUA_REFNIL) {
    luaL_unref(L, LUA_REGISTRYINDEX, b.config_ref);
  }
  if (g_env_max_body) max_body_stream = g_env_max_body;

  L = saved_L;
  lua_close(t);
  g_reloading = 0;
  return 0;
}

static void on_ctrl_signal(uv_signal_t *h, int signum)
{
  (void)h;
  if (signum == SIGHUP) {
    if (g_ctrl_shutdown) return;
    if (multi_reload_config() == 0) {
      log_file_writer_reconfigure();
      __atomic_add_fetch(&g_ctrl_reload_seq, 1, __ATOMIC_ACQ_REL);
      for (size_t i = 0; i < g_worker_count; i++) uv_async_send(&g_workers[i].ctrl);
      fprintf(stderr, "reload: dispatched to %zu worker(s)\n", g_worker_count);
    }
    return;
  }
  g_ctrl_shutdown = 1;
  if (g_ctrl_signal_state == 0) {
    g_ctrl_signal_state = 1;
    fprintf(stderr, "shutdown: draining %zu worker(s)\n", g_worker_count);
  } else {
    g_ctrl_force = 1;
    fprintf(stderr, "shutdown: forced\n");
  }
  for (size_t i = 0; i < g_worker_count; i++) uv_async_send(&g_workers[i].ctrl);
}

static int run_multi_worker(void)
{
  g_workers_done = 0;
  g_ctrl_force = 0;
  g_ctrl_shutdown = 0;
  g_ctrl_signal_state = 0;
  g_ctrl_reload_seq = 0;
  g_reloading = 0;

  if (uv_mutex_init(&g_cfg_init_mutex) != 0) return -1;
  if (uv_barrier_init(&g_init_barrier, (unsigned)g_worker_count) != 0) {
    uv_mutex_destroy(&g_cfg_init_mutex);
    return -1;
  }
  if (uv_loop_init(&g_ctrl_loop) != 0) {
    uv_barrier_destroy(&g_init_barrier);
    uv_mutex_destroy(&g_cfg_init_mutex);
    return -1;
  }

  uv_async_init(&g_ctrl_loop, &g_ctrl_done_async, on_worker_done);

  uv_signal_t sigint_h, sigterm_h, sighup_h;
  uv_signal_init(&g_ctrl_loop, &sigint_h);
  uv_signal_start(&sigint_h, on_ctrl_signal, SIGINT);
  uv_signal_init(&g_ctrl_loop, &sigterm_h);
  uv_signal_start(&sigterm_h, on_ctrl_signal, SIGTERM);
  uv_signal_init(&g_ctrl_loop, &sighup_h);
  uv_signal_start(&sighup_h, on_ctrl_signal, SIGHUP);

  g_workers = (worker_t *)calloc(g_worker_count, sizeof(worker_t));
  if (!g_workers) {
    fprintf(stderr, "out of memory for workers\n");
    return -1;
  }
  for (size_t i = 0; i < g_worker_count; i++) {
    g_workers[i].id = (int)i;
    if (uv_thread_create(&g_workers[i].thread, worker_thread_main, &g_workers[i]) != 0) {
      fprintf(stderr, "worker %zu: uv_thread_create failed\n", i);
      return -1;
    }
  }

  uv_run(&g_ctrl_loop, UV_RUN_DEFAULT);

  for (size_t i = 0; i < g_worker_count; i++) uv_thread_join(&g_workers[i].thread);

  /* 所有 worker 已停止生产，collector 做最后一次 drain，然后 file/发送线程收尾 */
  log_pipeline_stop();

  uv_close((uv_handle_t *)&g_ctrl_done_async, NULL);
  uv_close((uv_handle_t *)&sigint_h, NULL);
  uv_close((uv_handle_t *)&sigterm_h, NULL);
  uv_close((uv_handle_t *)&sighup_h, NULL);
  uv_run(&g_ctrl_loop, UV_RUN_NOWAIT);
  uv_loop_close(&g_ctrl_loop);

  free(g_workers);
  g_workers = NULL;
  uv_barrier_destroy(&g_init_barrier);
  uv_mutex_destroy(&g_cfg_init_mutex);
  return 0;
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
  reload_config();
}

int main(int argc, char **argv)
{
  const char *cfg = argc > 1 ? argv[1] : "config.lua";
  int cli_port = argc > 2 ? atoi(argv[2]) : 0;
  int check_mode = 0;

  if (argc > 1 && (strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--check") == 0)) {
    check_mode = 1;
    cfg = argc > 2 ? argv[2] : "config.lua";
    cli_port = 0;
  }
  if (cli_port <= 0) {
    const char *pe = getenv("HTTPD_PORT");
    if (pe && *pe) cli_port = atoi(pe);
  }
  g_cli_port = cli_port;

  const char *mb = getenv("HTTPD_MAX_BODY");
  if (mb && *mb) {
    unsigned long long v = strtoull(mb, NULL, 10);
    if (v > 0) g_env_max_body = (size_t)v;
  }

  signal(SIGPIPE, SIG_IGN);
  curl_global_init(CURL_GLOBAL_DEFAULT);

  /* 多 worker 只从配置文件的 server.workers 读取；--check 与旧 app.lua 模式固定单 worker */
  g_worker_count = check_mode ? 1 : (size_t)detect_workers(cfg);
  if (g_worker_count > 1) {
    snprintf(g_config_path, sizeof(g_config_path), "%s", cfg);
    g_log_pipeline = 1;
    g_log_init_done = 0;
    if (log_rings_alloc(g_worker_count) != 0) {
      fprintf(stderr, "out of memory for log rings\n");
      curl_global_cleanup();
      return 1;
    }
    int rc = run_multi_worker();
    log_rings_free();
    curl_global_cleanup();
    return rc == 0 ? 0 : 1;
  }

  config_defaults_init();
  init_lua(cfg, cli_port, check_mode);
  if (!check_mode) listen_snapshot_capture();
  if (g_env_max_body) max_body_stream = g_env_max_body;

  if (check_mode) {
    int rc = config_check_extra();
    if (rc != 0) {
      if (g_tls_gen) { tls_gen_unref(g_tls_gen); g_tls_gen = NULL; }
      free(g_listeners);
      curl_global_cleanup();
      lua_close(L);
      return 1;
    }
    printf("configuration file %s test is successful\n", cfg);
    if (g_tls_gen) { tls_gen_unref(g_tls_gen); g_tls_gen = NULL; }
    free(g_listeners);
    curl_global_cleanup();
    lua_close(L);
    return 0;
  }

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

  uv_timer_init(loop, &g_tls_check_timer);
  if (g_tls_enabled && g_tls_check_interval_ms > 0) {
    uv_timer_start(&g_tls_check_timer, tls_check_timer_cb,
                   (uint64_t)g_tls_check_interval_ms,
                   (uint64_t)g_tls_check_interval_ms);
  }
  uv_timer_init(loop, &g_revocation_timer);
  if (g_revocation.enabled && g_revocation.interval_ms > 0) {
    uv_timer_start(&g_revocation_timer, revocation_timer_cb,
                   (uint64_t)g_revocation.interval_ms,
                   (uint64_t)g_revocation.interval_ms);
  }

  start_listeners();

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
    revoked_store_t *rs = __atomic_load_n(&g_revoked, __ATOMIC_ACQUIRE);
    log_error(LOG_INFO, "revocation: enabled, %zu entries, periodic every %dms, provider=%s",
              rs ? rs->count : 0, g_revocation.interval_ms,
              g_revocation.provider_type);
  }
  log_error(LOG_INFO,
            "max_body=%zu idle_timeout=%us shutdown_timeout=%ums tcp{nodelay=%d keepalive=%d backlog=%d reuse_port=%d}",
            max_body_stream, g_idle_timeout_ms / 1000, g_shutdown_timeout_ms,
            g_tcp.nodelay, g_tcp.keepalive, g_tcp.backlog, g_tcp.reuse_port);

  uv_run(loop, UV_RUN_DEFAULT);

  log_shutdown();
  curl_global_cleanup();
  lua_close(L);
  return 0;
}
