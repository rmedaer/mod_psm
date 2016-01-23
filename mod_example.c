/**
 * Include core server components.
 */
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_strings.h"
#include "util_filter.h"


#define COOKIE_SEPARATOR "=;"


static const char *cookie_get_name(request_rec *r, const char *header)
{ 
    char *last;
    return apr_strtok(apr_pstrdup(r->pool, header), COOKIE_SEPARATOR, &last);
}

static const char *cookie_get_value(request_rec *r, const char *header)
{ 
    char *last;
    apr_strtok(apr_pstrdup(r->pool, header), COOKIE_SEPARATOR, &last);
    return apr_strtok(NULL, COOKIE_SEPARATOR, &last);
}


static int cookie_save(void *rec, const char *key, const char *val)
{
    ap_filter_t *f = (ap_filter_t *) rec;
    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, f->c->pool, "Set my cookie: %s: %s",
            cookie_get_name(f->r, val),
            cookie_get_value(f->r, val));

    return TRUE;
}

apr_status_t example_output_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
    // Execute filter only on initial request
    if (! ap_is_initial_req(f->r)) {
        return ap_pass_brigade(f->next, bb);
    }

    ap_log_perror(APLOG_MARK, APLOG_DEBUG, APLOG_NOERRNO, f->c->pool,
            "Replacing `Set-Cookie` headers by session id.");

    // List every 'Set-Cookie' headers
    apr_table_do(cookie_save, f, f->r->headers_out, "Set-Cookie", NULL);

    // Replace 'Set-Cookie' with session ID 
    apr_table_set(f->r->headers_out, "Set-Cookie", "ad12e98754bc");
    
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static void example_insert_filter(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Insert filter without handler for %s", r->hostname);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "TODO: test module config");
    ap_add_output_filter("out-test-filter",  NULL, r, r->connection);
}

static int example_handler(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Request %s", r->hostname);
    apr_table_set(r->headers_in, "Cookie", "truc=cookiereplacement");
    return DECLINED;
}

static void mod_example_register_hooks(apr_pool_t *p)
{
    ap_hook_insert_filter(example_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter("out-test-filter", example_output_filter, NULL, AP_FTYPE_RESOURCE);


    ap_hook_handler(example_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

module AP_MODULE_DECLARE_DATA mod_example_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    mod_example_register_hooks
};
