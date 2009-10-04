#include <assert.h>
#include <curl/curl.h>
#include "apr.h"
#include "apr_lib.h"
#include "apr_buckets.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#define CORE_PRIVATE
#include "http_request.h"
#include "http_core.h"
#include "util_filter.h"

module AP_MODULE_DECLARE_DATA reproxy_module;

typedef struct {
  int enabled; /* -1: unset, 0: disabled, 1: enabled */
} reproxy_conf;

static void* config_create(apr_pool_t* p)
{
  reproxy_conf* conf = apr_palloc(p, sizeof(reproxy_conf));
  conf->enabled = -1;
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
  conf->enabled = override->enabled != -1 ? override->enabled : base->enabled;
  return conf;
}

static const char* reproxy_cmd(cmd_parms* cmd, void* _conf, int flag)
{
  reproxy_conf* conf = _conf;
  conf->enabled = flag != 0;
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

static size_t reproxy_curl_cb(const void* ptr, size_t size, size_t nmemb,
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
  
  /* pass thru on error, subreq, or default handler */
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
  unset_header(r, "Content-Encoding");
  unset_header(r, "Last-Modified");
  unset_header(r, "ETag");
  
  { /* retrieve data using curl */
    CURL* curl = curl_easy_init();
    reproxy_curl_cb_info info;
    assert(curl != NULL);
    info.filt = f;
    info.bb = in_bb;
    curl_easy_setopt(curl, CURLOPT_URL, reproxy_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, reproxy_curl_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &info);
    /* TODO: check response */curl_easy_perform(curl);
    curl_easy_cleanup(curl);
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
  if (conf->enabled == -1)
    conf = (reproxy_conf*)ap_get_module_config(r->server->module_config,
					       &reproxy_module);
  if (conf->enabled == 1)
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
