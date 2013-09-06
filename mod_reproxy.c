/* 
 * Copyright 2009 Kazuho Oku
 * Copyright 2010 Cybozu Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <assert.h>
#include "apr_fnmatch.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_mpm.h"
#include "picohttpparser/picohttpparser.h"

module AP_MODULE_DECLARE_DATA reproxy_module;

#define REPROXY_VERSION 0.02
#define REPROXY_VERSION_STR "0.02"

#define REPROXY_FLAG_UNSET -1
#define REPROXY_FLAG_OFF 0
#define REPROXY_FLAG_ON 1

#define REPROXY_DEFAULT_REQUEST_TIMEOUT 30
#define REPROXY_DEFAULT_RESPONSE_TIMEOUT 30
#define REPROXY_TIMEOUT_UNSET -1

#define REPROXY_DEFAULT_MAX_REDIRECTS 5
#define REPROXY_MAX_REDIRECTS_UNSET -1

#define MAX_RESPONSE_SZ 16384

#define REPROXY_CONF_IGNORE_POS 0
#define REPROXY_CONF_FORWARD_POS 1

typedef struct {
  int enabled;
  int request_timeout;
  int response_timeout;
  int max_redirects;
  ap_regex_t* limit_re;
  char **ignore_headers;
  int    num_ignore_headers;
  char **forward_headers;
  int    num_forward_headers;
} reproxy_conf;

static struct {
  size_t headers;
  size_t num;
} conf_offset[] = {
  {APR_OFFSETOF(reproxy_conf, ignore_headers),
   APR_OFFSETOF(reproxy_conf, num_ignore_headers)},
  {APR_OFFSETOF(reproxy_conf, forward_headers),
   APR_OFFSETOF(reproxy_conf, num_forward_headers)}
};

static void* config_create(apr_pool_t* p)
{
  reproxy_conf* conf = apr_palloc(p, sizeof(reproxy_conf));
  conf->enabled = REPROXY_FLAG_UNSET;
  conf->request_timeout = REPROXY_TIMEOUT_UNSET;
  conf->response_timeout = REPROXY_TIMEOUT_UNSET;
  conf->max_redirects = REPROXY_MAX_REDIRECTS_UNSET;
  conf->limit_re = NULL;
  conf->ignore_headers = NULL;
  conf->num_ignore_headers = 0;
  conf->forward_headers = NULL;
  conf->num_forward_headers = 0;
  return conf;
}

static void* reproxy_config_server_create(apr_pool_t* p, server_rec* r)
{
  return config_create(p);
}

static void* reproxy_config_perdir_create(apr_pool_t* p, char* path)
{
  return config_create(p);
}  

static void* reproxy_config_merge(apr_pool_t* p, void* _base, void* _override)
{
  reproxy_conf* base = _base,
    * override = _override,
    * conf = apr_palloc(p, sizeof(reproxy_conf));
  
#define SET(prop, unset) \
  conf->prop = override->prop != unset ? override->prop : base->prop
  
  SET(enabled, REPROXY_FLAG_UNSET);
  SET(request_timeout, REPROXY_TIMEOUT_UNSET);
  SET(response_timeout, REPROXY_TIMEOUT_UNSET);
  SET(max_redirects, REPROXY_MAX_REDIRECTS_UNSET);
  SET(limit_re, NULL);
  SET(ignore_headers, NULL);
  SET(num_ignore_headers, 0);
  SET(forward_headers, NULL);
  SET(num_forward_headers, 0);
  
#undef SET
  
  return conf;
}

static const char* set_reproxy_flag(cmd_parms* cmd, void* _conf, int flag)
{
  reproxy_conf* conf = _conf;
  conf->enabled = flag ? REPROXY_FLAG_ON : REPROXY_FLAG_OFF;
  return NULL;
}

static const char* set_reproxy_intval(cmd_parms* cmd, void* _conf,
				      const char* value)
{
  reproxy_conf* conf = _conf;
  *(int*)((char*)conf + (size_t)cmd->info) = atoi(value);
  return NULL;
}

static const char* set_reproxy_limit_re(cmd_parms* cmd, void* _conf,
					const char* value)
{
  reproxy_conf* conf = _conf;
  if ((conf->limit_re = ap_pregcomp(cmd->pool, value,
				    AP_REG_EXTENDED | AP_REG_NOSUB))
      == NULL) {
    return "Failed to compile regular expression";
  }
  return NULL;
}

static const char* set_reproxy_string_to_table(cmd_parms* cmd, void* _conf,
                    const char* value)
{
  reproxy_conf* conf = _conf;
  size_t pos = (size_t)cmd->info;
  char **new;
  char *copy;
  char ***table = (char***)((char*)conf + conf_offset[pos].headers);
  int *num = (int*)((char*)conf + conf_offset[pos].num);

  new = apr_palloc( cmd->pool, sizeof(char *) * (*num + 1 ) );
  if ( *table != NULL ) {
    memcpy( new, *table, *num * sizeof(char *) );
  }
  *table = new;
  copy = apr_palloc( cmd->pool, sizeof(char) * ( strlen(value) + 1 ) );
  memcpy( copy, value, strlen(value) * sizeof(char) + 1 );
  copy[ strlen(value) ] = '\0';
  (*table)[ (*num)++ ] = copy;

  return NULL;
}

static void unset_header(request_rec* r, const char* n)
{
  apr_table_unset(r->headers_out, n);
  apr_table_unset(r->err_headers_out, n);
}

static int parse_url(const char* url, char** hostport, const char** path,
		     char** host, apr_port_t* port, apr_pool_t* pool)
{
  const char* hp_start, * hp_end;
  char* scope_id;
  /* check and skip scheme */
  if (strncmp(url, "http://", 7) != 0) {
    return 0;
  }
  hp_start = url + 7;
  /* locate the end of hostport */
  if ((hp_end = strchr(hp_start, '/')) != NULL) {
    *path = hp_end;
  } else {
    hp_end = hp_start + strlen(hp_start);
    *path = "/";
  }
  /* copy hostport to string */
  *hostport = apr_palloc(pool, hp_end - hp_start + 1);
  memcpy(*hostport, hp_start, hp_end - hp_start);
  (*hostport)[hp_end - hp_start] = '\0';
  /* parse */
  *port = 0;
  if (apr_parse_addr_port(host, &scope_id, port, *hostport, pool) != APR_SUCCESS
      || host == NULL || scope_id) {
    return 0;
  }
  if (*port == 0) {
    *port = 80;
  }
  /* success */
  return 1;
}

static apr_status_t set_timeout_or_default(apr_socket_t* sock, int timeout,
					   int default_timeout)
{
  return apr_socket_timeout_set(sock,
				(timeout != REPROXY_TIMEOUT_UNSET
				 ? timeout : default_timeout)
				* 1000000);
}

static apr_status_t send_fully(apr_socket_t* sock, const char* start,
			       const char* end)
{
  const char* p = start;
  apr_size_t l;
  apr_status_t rv;
  while ((l = end - p) != 0) {
    if ((rv = apr_socket_send(sock, p, &l)) != APR_SUCCESS
	&& ! APR_STATUS_IS_EAGAIN(rv)) {
      return rv;
    }
    p += l;
  }
  return APR_SUCCESS;
}

static char* find_phr_header(struct phr_header* headers, size_t num_headers,
			     const char* name, apr_pool_t* pool)
{
  size_t i;
  for (i = 0; i != num_headers; i++)
    if (strncasecmp(headers[i].name, name, headers[i].name_len) == 0) {
      char* value = apr_palloc(pool, headers[i].value_len + 1);
      memcpy(value, headers[i].value, headers[i].value_len);
      value[headers[i].value_len] = '\0';
      return value;
    }
  return NULL;
}

static apr_off_t fetch_phr_content_length(struct phr_header* headers,
					  size_t num_headers, apr_pool_t* pool)
{
  const char* value_str = find_phr_header(headers, num_headers,
					  "content-length", pool);
  apr_off_t value;
  if (value_str != NULL
      && apr_strtoff(&value, value_str, NULL, 10) == APR_SUCCESS)
    return value;
  return -1;
}

static char* make_header_field(apr_table_t* headers, reproxy_conf* conf,
			       apr_pool_t* p)
{
  char *buf;
  size_t buf_sz = 0;
  size_t write_sz = 0;
  size_t num = conf->num_forward_headers;
  char *targets = apr_pcalloc(p, num);
  size_t i;
  for (i = 0; i < num; ++i) {
    char *key = conf->forward_headers[i];
    const char *val = apr_table_get(headers, key);
    if (val) {
      /* 4 means strlen(": ") + strlen("\r\n") */
      buf_sz += strlen(key) + strlen(val) + 4;
      targets[i] = 1;
    }
  }
  if (buf_sz == 0)
    return "";
  buf = apr_palloc(p, buf_sz + 1);
  for (i = 0; i < num; ++i)
    if (targets[i]) {
      char *key = conf->forward_headers[i];
      const char *val = apr_table_get(headers, key);
      write_sz += sprintf(buf + write_sz, "%s: %s\r\n", key, val);
    }
  return buf;
}

static apr_status_t send_reproxy_request(reproxy_conf* conf, request_rec* r,
					 const char* url, apr_socket_t** _sock)
{
  char* hostport, * host, * req;
  const char* path;
  apr_port_t port;
  apr_sockaddr_t* destsa;
  apr_socket_t* sock = NULL;
  apr_status_t rv;
  
  /* parse url */
  if (! parse_url(url, &hostport, &path, &host, &port, r->pool)) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		 "reproxy: failed to parse reproxy url: %s", url);
    rv = HTTP_INTERNAL_SERVER_ERROR;
    goto ON_EXIT;
  }
  /* resolve address */
  if ((rv = apr_sockaddr_info_get(&destsa, host, APR_UNSPEC, port, 0, r->pool))
      != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
		 "reproxy: failed to resolve address for url: %s", url);
    goto ON_EXIT;
  }
  /* create socket */
  if ((rv = apr_socket_create(&sock, destsa->family, SOCK_STREAM, 0, r->pool))
      != APR_SUCCESS) {
    sock = NULL; /* just in case */
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
		 "reproxy: apr_socket_create failed while trying to retrieve url: %s",
		 url);
    rv = HTTP_INTERNAL_SERVER_ERROR;
    goto ON_EXIT;
  }
  /* set request timeout */
  set_timeout_or_default(sock, conf->request_timeout,
			 REPROXY_DEFAULT_REQUEST_TIMEOUT);
  /* connect */
  if ((rv = apr_socket_connect(sock, destsa)) != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
		 "reproxy: connection failed for URL: %s", url);
    rv = HTTP_INTERNAL_SERVER_ERROR;
    goto ON_EXIT;
  }
  
  /* build and send request (no need to set timeout since all request will go
   * into SNDBUF anyway */
  req = apr_psprintf(r->pool,
		     "%s %s HTTP/1.0\r\n"
		     "Host: %s\r\n"
		     "User-Agent: mod_reproxy/" REPROXY_VERSION_STR "\r\n"
		     "%s" /* forwarding client headers */
		     "\r\n",
		     r->header_only ? "HEAD" : "GET", path, hostport,
		     make_header_field(r->headers_in, conf, r->pool));
  if ((rv = send_fully(sock, req, req + strlen(req))) != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
		 "reproxy: an error occured while sending request to url: %s\n",
		 url);
    rv = HTTP_INTERNAL_SERVER_ERROR;
    goto ON_EXIT;
  }
  
  /* set timeout to response timeout */
  set_timeout_or_default(sock, conf->response_timeout,
			 REPROXY_DEFAULT_RESPONSE_TIMEOUT);
  
 ON_EXIT:
  if (rv != APR_SUCCESS && sock != NULL) {
    apr_socket_close(sock);
    sock = NULL;
  }
  *_sock = sock;
  return rv;
}

static apr_status_t handle_reproxy_response(reproxy_conf *conf, request_rec* r,
                        const char *url,
					    apr_socket_t* sock,
					    char* buf, char** redirect_url,
					    apr_off_t* content_length,
					    char** buffered_content,
					    apr_size_t* buffered_content_length)
{
  apr_size_t bufsz = 0, reqsz;
  apr_status_t rv;
  int minor_ver, status;
  const char* msg;
  struct phr_header headers[128];
  size_t msg_len, num_headers;
  
  *redirect_url = NULL;
  *content_length = -1;
  *buffered_content = NULL;
  *buffered_content_length = 0;
  
  /* read response */
  do {
    apr_size_t l = MAX_RESPONSE_SZ - bufsz;
    rv = apr_socket_recv(sock, buf + bufsz, &l);
    if (APR_STATUS_IS_EAGAIN(rv)) {
      continue;
    } else if (l == 0 || rv != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
		   "reproxy: an error occurred while reading response for url:"
		   "%s\n",
		   url);
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* try to parse the response */
    num_headers = sizeof(headers) / sizeof(headers[0]);
    reqsz = phr_parse_response(buf, bufsz + l, &minor_ver, &status, &msg,
			       &msg_len, headers, &num_headers, bufsz);
    bufsz += l;
    switch (reqsz) {
    case -1: /* error */
      ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
		   "reproxy: received corrupt HTTP response for url: %s\n",
		   url);
      return HTTP_INTERNAL_SERVER_ERROR;
    case -2: /* partial */
      break;
    default: /* success */
      goto PARSE_COMPLETE;
    }
  } while (bufsz < MAX_RESPONSE_SZ);
  ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
	       "reproxy: response is too large for url: %s", url);
  return HTTP_INTERNAL_SERVER_ERROR;
  
 PARSE_COMPLETE:
  { /* Copy headers so that it's propagated */
    int i;
    for (i = 0; i < num_headers; i++) {
      char *name, *value;
      int ignum;
      int ignore = 0;

      for ( ignum = 0; ignum < conf->num_ignore_headers; ignum++ ) {
        if ( strncasecmp(headers[i].name, conf->ignore_headers[ignum], headers[i].name_len) == 0 ) {
          ignore = 1;
          break;
        }
      }

      if (ignore) {
        break;
      }

      name = apr_palloc(r->pool, headers[i].name_len + 1);
      memcpy(name, headers[i].name, headers[i].name_len);
      name[headers[i].name_len] = '\0';

      value = apr_palloc(r->pool, headers[i].value_len + 1);
      memcpy(value, headers[i].value, headers[i].value_len);
      value[headers[i].value_len] = '\0';


      apr_table_add( r->headers_out, name, value );
    }
  }

  switch (status) {
  case 200: /* ok, fill in the values */
  case 206: /* partial response */
  case 404: /* pass though some other values, too */
  case 416: /* illegal range request */
    r->status = status;
    r->status_line = ap_get_status_line(status);
    break;
  case 301: case 302: case 303: case 307: /* redicet */
    if ((*redirect_url = find_phr_header(headers, num_headers, "location",
					 r->pool))
	== NULL) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		   "reproxy: got %d response without a location header for url:"
		   " %s\n",
		   status, url);
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    return APR_SUCCESS;
  default:
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		 "reproxy: got %d response for url: %s\n", status, url);
    /* 503 should be returned as 503, others are converted to 500 */
    return status == 503 ? 503 : HTTP_INTERNAL_SERVER_ERROR;
  }

  if ( ! r->header_only ) {
    /* response is 200, fill in the values */
    *content_length = fetch_phr_content_length(headers, num_headers, r->pool);
    if (bufsz != reqsz) {
      *buffered_content = buf + reqsz;
      *buffered_content_length = bufsz - reqsz;
    }
  }
  return APR_SUCCESS;
}

static apr_status_t rewrite_response(ap_filter_t* filt,
				     apr_bucket_brigade* in_bb,
				     const char* url)
{
  reproxy_conf* conf = filt->ctx;
  request_rec* r = filt->r;
  apr_socket_t* sock = NULL;
  int left_redirect_cnt;
  char* response_buf = apr_palloc(r->pool, MAX_RESPONSE_SZ);
  char* buffered_content;
  apr_size_t buffered_content_length;
  apr_off_t clength, sent_length = 0;
  apr_status_t rv;
  
  /* send request / handle response, until we get a non-redirecting response */
  for (left_redirect_cnt = conf->max_redirects != REPROXY_MAX_REDIRECTS_UNSET
	 ? conf->max_redirects : REPROXY_DEFAULT_MAX_REDIRECTS;
       ;
       --left_redirect_cnt) {
    char* redirect_url;
    /* check if access is allowed */
    if (conf->limit_re != NULL
	&& ap_regexec(conf->limit_re, url, 0, NULL, AP_REG_EXTENDED) != 0) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		   "reproxy: access denied by rule to url: %s", url);
      rv = HTTP_INTERNAL_SERVER_ERROR;
      goto ON_EXIT;
    }
    /* connect to and send request */
    if ((rv = send_reproxy_request(conf, r, url, &sock)) != APR_SUCCESS)
      goto ON_EXIT;
    /* handle response */
    if ((rv = handle_reproxy_response(conf, r, url, sock, response_buf,
                      &redirect_url, &clength, &buffered_content,
				      &buffered_content_length))
	!= APR_SUCCESS)
      goto ON_EXIT;
    if (redirect_url == NULL)
      break;
    /* is a redirect */
    if (left_redirect_cnt <= 0) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		   "reproxy: too many redirects while trying to serve url: %s",
		   url);
      rv = HTTP_INTERNAL_SERVER_ERROR;
      goto ON_EXIT;
    }
    apr_socket_close(sock);
    sock = NULL;
    url = redirect_url;
  }
  
  /* send already-received data */
  if (buffered_content_length != 0) {
    void* d;
    apr_bucket* b;
    apr_size_t sz = buffered_content_length;
    if (clength != -1 && clength < sz)
      sz = clength;
    if ((d = malloc(sz)) == NULL) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "reproxy: no memory");
      rv = HTTP_INTERNAL_SERVER_ERROR;
      goto ON_EXIT;
    }
    memcpy(d, buffered_content, sz);
    b = apr_bucket_heap_create(d, sz, free, in_bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(in_bb, b);
    sent_length += sz;
    if ((rv = ap_pass_brigade(filt->next, in_bb)) != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
		   "reproxy: failed to pass response to the next filter while processing url: %s",
		   url);
      goto ON_EXIT;
    }
  }
  
  /* send all data */
  if ( ! r->header_only ) {
    while (clength == -1 || sent_length != clength) {
      void* d;
      apr_bucket* b;
      apr_size_t l = 131072; /* FIXME should the bufsz be configurable? */
      if (clength != -1 && clength - sent_length < l)
        l = clength - sent_length;
      if ((d = malloc(l)) == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "reproxy: no memory");
        rv = HTTP_INTERNAL_SERVER_ERROR;
      }
      do {
        rv = apr_socket_recv(sock, d, &l);
      } while (APR_STATUS_IS_EAGAIN(rv));
      if (l == 0 && APR_STATUS_IS_EOF(rv)) {
        free(d);
        break;
      } else if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
  		   "reproxy: an error occurred while transmitting content from url: %s",
  		   url);
        free(d);
        goto ON_EXIT;
      }
      b = apr_bucket_heap_create(d, l, free, in_bb->bucket_alloc);
      APR_BRIGADE_INSERT_TAIL(in_bb, b);
      sent_length += l;
      if ((rv = ap_pass_brigade(filt->next, in_bb)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
  		   "reproxy: failed to pass response to the next filter while processing url: %s",
  		   url);
        goto ON_EXIT;
      }
    }
  }
  
 ON_EXIT:
  if (sent_length == 0 && rv != APR_SUCCESS) {
    r->status = rv;
    ap_send_error_response(r, 0);
  }
  if (sock != NULL)
    apr_socket_close(sock);
  return rv;
}

static apr_status_t reproxy_output_filter(ap_filter_t* f,
					  apr_bucket_brigade* in_bb)
{
  request_rec* r =f->r;
  const char* reproxy_url;
  
  /* pass thru by request types */
  if (r->status != HTTP_OK || r->main != NULL 
      || (r->handler != NULL && strcmp(r->handler, "default-handler") == 0))
    goto PASS_THRU;
  
  /* obtain and erase x-reproxy-url header or pass through */
  if ((reproxy_url = apr_table_get(r->headers_out, "x-reproxy-url")) != NULL)
    apr_table_unset(r->headers_out, "x-reproxy-url");
  if (reproxy_url == NULL || *reproxy_url == '\0')
    if ((reproxy_url = apr_table_get(r->err_headers_out, "x-reproxy-url"))
	!= NULL)
      apr_table_unset(r->err_headers_out, "x-reproxy-url");
  if (reproxy_url == NULL || *reproxy_url == '\0')
    goto PASS_THRU;
  
  /* drop all content and headers related */
  while (! APR_BRIGADE_EMPTY(in_bb)) {
    apr_bucket* b = APR_BRIGADE_FIRST(in_bb);
    apr_bucket_delete(b);
  }
  r->eos_sent = 0;
  r->clength = 0;
  unset_header(r, "Content-Length");
  unset_header(r, "Transfer-Encoding");
  unset_header(r, "Last-Modified");
  unset_header(r, "ETag");
  
  /* retrieve data from another host and send it */
  return rewrite_response(f, in_bb, reproxy_url);
  
PASS_THRU:
  ap_remove_output_filter(f);
  return ap_pass_brigade(f->next, in_bb);
}

static void reproxy_insert_output_filter(request_rec* r)
{
  reproxy_conf* conf =
    (reproxy_conf*)ap_get_module_config(r->per_dir_config, &reproxy_module);
  if (conf->enabled == REPROXY_FLAG_UNSET)
    conf = (reproxy_conf*)ap_get_module_config(r->server->module_config,
					       &reproxy_module);
  if (conf->enabled == REPROXY_FLAG_ON)
    ap_add_output_filter("REPROXY", conf, r, r->connection);
}

static const command_rec reproxy_cmds[] = {
  AP_INIT_FLAG("Reproxy", set_reproxy_flag, NULL, OR_OPTIONS, "On|Off"),
  AP_INIT_TAKE1("ReproxyRequestTimeout", set_reproxy_intval,
		(void*)APR_OFFSETOF(reproxy_conf, request_timeout), OR_OPTIONS,
		"request timeout of the reproxy connection (in seconds)"),
  AP_INIT_TAKE1("ReproxyResponseTimeout", set_reproxy_intval,
		(void*)APR_OFFSETOF(reproxy_conf, response_timeout), OR_OPTIONS,
		"response timeout of the reproxy connection (in seconds)"),
  AP_INIT_TAKE1("ReproxyMaxRedirects", set_reproxy_intval,
		(void*)APR_OFFSETOF(reproxy_conf, max_redirects), OR_OPTIONS,
		"max redirection # of the reproxy connection (in seconds)"),
  AP_INIT_TAKE1("ReproxyLimitURL", set_reproxy_limit_re, NULL, OR_OPTIONS,
		"regex to limit access of the reproxy module"),
  AP_INIT_TAKE1("ReproxyIgnoreHeader", set_reproxy_string_to_table,
                (void*)REPROXY_CONF_IGNORE_POS, OR_OPTIONS,
                "do not propagate these headers"),
  AP_INIT_TAKE1("ReproxyForwardClientHeader", set_reproxy_string_to_table,
                (void*)REPROXY_CONF_FORWARD_POS, OR_OPTIONS,
                "header of client request forwarding to reproxy target"),
  { NULL },
};

static void reproxy_register_hooks(apr_pool_t* p)
{
  ap_register_output_filter("REPROXY", reproxy_output_filter, NULL,
			    AP_FTYPE_CONTENT_SET);
  ap_hook_insert_filter(reproxy_insert_output_filter, NULL, NULL,
			APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA reproxy_module = {
  STANDARD20_MODULE_STUFF,
  reproxy_config_perdir_create,
  reproxy_config_merge,
  reproxy_config_server_create,
  reproxy_config_merge,
  reproxy_cmds,
  reproxy_register_hooks
};

#include "picohttpparser/picohttpparser.c"
