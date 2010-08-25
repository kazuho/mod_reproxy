/* 
 * Copyright 2009 Kazuho Oku
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
#include <curl/curl.h>
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_mpm.h"

module AP_MODULE_DECLARE_DATA reproxy_module;

#define REPROXY_VERSION 0.01
#define REPROXY_VERSION_STR "0.01"

#define REPROXY_FLAG_UNSET -1
#define REPROXY_FLAG_OFF 0
#define REPROXY_FLAG_ON 1

typedef struct {
  int enabled;
} reproxy_conf;

static void* config_create(apr_pool_t* p)
{
  reproxy_conf* conf = apr_palloc(p, sizeof(reproxy_conf));
  conf->enabled = REPROXY_FLAG_UNSET;
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
  conf->enabled = override->enabled != REPROXY_FLAG_UNSET
    ? override->enabled : base->enabled;
  return conf;
}

static const char* reproxy_cmd(cmd_parms* cmd, void* _conf, int flag)
{
  reproxy_conf* conf = _conf;
  conf->enabled = flag ? REPROXY_FLAG_ON : REPROXY_FLAG_OFF;
  return NULL;
}

static void unset_header(request_rec* r, const char* n)
{
  apr_table_unset(r->headers_out, n);
  apr_table_unset(r->err_headers_out, n);
}

typedef struct {
  ap_filter_t* filt;
  apr_bucket_brigade* bb;
} reproxy_curl_cb_info;

static size_t reproxy_curl_header_cb(const void* ptr, size_t size, size_t nmemb,
				     void* _info)
{
  reproxy_curl_cb_info* info = _info;
  
  if (strncmp(ptr, "HTTP/1.", sizeof("HTTP/1.") - 1) == 0) {
    int minor_ver, status;
    if (sscanf(ptr, "HTTP/1.%d %d ", &minor_ver, &status) == 2 && status != 200)
      info->filt->r->status = status;
  } else if (strncasecmp(ptr, "content-type:", sizeof("content-type:") - 1)
	     == 0) {
    request_rec* r = info->filt->r;
    const char* s = (const char*)ptr + sizeof("content-type:") - 1,
      * e = (const char*)ptr + size * nmemb - 1;
    for (; s <= e; --e)
      if (*e != '\r' && *e != '\n')
	break;
    for (; s <= e; ++s)
      if (*s != ' ' && *s != '\t')
	break;
    if (s <= e)
      ap_set_content_type(r, apr_pstrndup(r->pool, s, e - s + 1));
  }
  
  return nmemb;
}

static size_t reproxy_curl_write_cb(const void* ptr, size_t size, size_t nmemb,
				    void* _info)
{
  reproxy_curl_cb_info* info = _info;
  void* d;
  apr_bucket* b;
  if (nmemb == 0)
    return 0;
  if ((d = malloc(size * nmemb)) == NULL)
    return 0;
  memcpy(d, ptr, size * nmemb);
  if ((b = apr_bucket_heap_create(d, size * nmemb, free,
				  info->bb->bucket_alloc))
      == NULL)
    return 0;
  APR_BRIGADE_INSERT_TAIL(info->bb, b);
  if (ap_pass_brigade(info->filt->next, info->bb) != APR_SUCCESS)
    return 0;
  return nmemb;
}

static apr_status_t reproxy_output_filter(ap_filter_t* f,
					  apr_bucket_brigade* in_bb)
{
  request_rec* r =f->r;
  const char* reproxy_url;
  
  /* pass thru by request types */
  if (r->status != HTTP_OK || r->main != NULL || r->header_only
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
  unset_header(r, "Content-Encoding");
  unset_header(r, "Last-Modified");
  unset_header(r, "ETag");
  
  { /* retrieve data using curl */
    CURL* curl = curl_easy_init();
    CURLcode ret;
    reproxy_curl_cb_info info;
    int threaded_mpm;
    assert(curl != NULL);
    info.filt = f;
    info.bb = in_bb;
    ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, threaded_mpm);
    curl_easy_setopt(curl, CURLOPT_URL, reproxy_url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &info);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, reproxy_curl_header_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &info);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, reproxy_curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
		     apr_psprintf(r->pool,
				  "mod_reproxy/" REPROXY_VERSION_STR " %s",
				  curl_version()));
    ret = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (ret != 0) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		   "reproxy: libcurl returned error (%d) while trying to retrieve url: %s",
		   ret, reproxy_url);
      r->status = HTTP_INTERNAL_SERVER_ERROR;
      ap_send_error_response(r, 0);
      return HTTP_INTERNAL_SERVER_ERROR;
    }
  }
  APR_BRIGADE_INSERT_TAIL(in_bb, apr_bucket_eos_create(in_bb->bucket_alloc));
  
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
    ap_add_output_filter("REPROXY", NULL, r, r->connection);
}

static const command_rec reproxy_cmds[] = {
  AP_INIT_FLAG("Reproxy", reproxy_cmd, NULL, OR_OPTIONS, "On|Off"),
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
