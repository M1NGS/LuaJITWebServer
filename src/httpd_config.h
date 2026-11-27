#ifndef HTTPD_CONFIG_H
#define HTTPD_CONFIG_H

#include <stddef.h>
#include <stdint.h>

/*
 * 配置结构体唯一来源（C 与 LuaJIT FFI 共用）。
 *
 * CDEF-BEGIN/CDEF-END 之间的内容会被 tools/gen_cdef.sh 原样提取给
 * ffi.cdef()，因此这一段只能用 POD 类型：
 *   - 使用 int32_t / size_t / char[N]，不要用 bool、位域、枚举、#pragma pack
 *   - 不要 include 其他头文件
 */

/* CDEF-BEGIN */
typedef struct httpd_name_value_s {
  char name[96];
  char value[512];
} httpd_name_value_t;

typedef struct httpd_log_file_cfg_s {
  int32_t enabled;
  int32_t access_on;
  int32_t error_on;
  int32_t level;              /* -1 = 继承 httpd_log_cfg_t.level */
  char access_path[512];
  char error_path[512];
  size_t max_bytes;
  int32_t flush_ms;
  int32_t rotate_ms;
  size_t rotate_size;
  int32_t rotate_keep;
} httpd_log_file_cfg_t;

typedef struct httpd_log_otlp_cfg_s {
  int32_t enabled;
  int32_t access_on;
  int32_t error_on;
  int32_t level;              /* -1 = 继承 */
  char endpoint[1024];        /* 已补默认 /v1/logs 的完整 URL */
  char ca[512];
  int32_t verify;
  char service_name[128];
  httpd_name_value_t resource[8];
  int32_t nresource;
  httpd_name_value_t headers[8];
  int32_t nheaders;
  int32_t batch_max_records;
  size_t batch_max_bytes;
  int32_t flush_ms;
  size_t queue_max_bytes;
  int32_t timeout_ms;
  int32_t max_retries;
} httpd_log_otlp_cfg_t;

typedef struct httpd_log_syslog_cfg_s {
  int32_t enabled;
  int32_t access_on;
  int32_t error_on;
  int32_t level;              /* -1 = 继承 */
  int32_t transport;          /* 0=udp 1=tcp 2=tls 3=unix */
  char host[256];
  int32_t port;
  char path[512];
  int32_t format;             /* 0=rfc5424 1=rfc3164 */
  int32_t facility;           /* 0..23 */
  char tag[64];
  size_t queue_max_bytes;
  int32_t reconnect_ms;
  char ca[512];
  int32_t verify;
} httpd_log_syslog_cfg_t;

typedef struct httpd_log_cfg_s {
  int32_t level;              /* 全局 error 级别（0=error .. 3=debug） */
  httpd_log_file_cfg_t file;
  httpd_log_otlp_cfg_t otlp;
  httpd_log_syslog_cfg_t syslog;
} httpd_log_cfg_t;

typedef struct httpd_config_s {
  int32_t version;            /* 结构版本；ABI 断言用 */
  httpd_log_cfg_t log;
  /* P2：server/tls/revocation 等配置迁入这里 */
} httpd_config_t;
/* CDEF-END */

#endif
