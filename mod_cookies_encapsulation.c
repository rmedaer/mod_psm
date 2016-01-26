/**
 *
 * NOTE: The internal module's logic is highly inspired from mod_rewrite for
 * configuraiton.
 *
 */


/**
 * Include core server components.
 */
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <util_filter.h>
#include "mod_cookies_encapsulation.h"


static char *trim_spaces(char *str)
{
    char *out;

    // Trim leading space
    while(apr_isspace(*str)) str++;

    if(*str == '\0')  // All spaces?
        return str;

    // Trim trailing space
    out = str + strlen(str) - 1;

    while(out > str && apr_isspace(*out)) out--;

    // Write new null terminator
    *(out + 1) = '\0';

    return str;
}


static char *cookie_get_name(request_rec *r, const char *header)
{ 
    char *next;
    return apr_strtok(apr_pstrdup(r->pool, header), "=", &next);
}

static char *cookie_get_value(request_rec *r, const char *header)
{ 
    char *next;
    apr_strtok(apr_pstrdup(r->pool, header), "=", &next);
    return apr_strtok(NULL, "=", &next);
}

/**
 * Parse a Cookie header value to extract a cem_cookie struct.
 */
static cem_cookie_entry *parse_cookie(request_rec *r, const char *header)
{
    char *next;
    char *token;
    cem_cookie_entry *cookie;
    cem_cookie_entry *head;

    head = NULL;

    token = apr_strtok(apr_pstrdup(r->pool, header), ";", &next);
    if (token == NULL) return NULL;

    do {
        cookie = (cem_cookie_entry *)apr_pcalloc(r->pool, sizeof(cem_cookie_entry));

        token = trim_spaces(token);
        if (! strlen(token)) continue;

        // Some space in the pool for my cookie
        cookie->v = (cem_cookie *)apr_pcalloc(r->pool, sizeof(cem_cookie));

        cookie->v->name  = cookie_get_name(r, token);
        cookie->v->value = cookie_get_value(r, token);

        cookie->next = head;
        head = cookie;
    } while ((token = apr_strtok(NULL, ";", &next)) != NULL);

    cookie = head;
    return cookie;
}

static cem_cookie *parse_set_cookie(request_rec * r, const char *header)
{
    char *next;
    char *token;
    unsigned int first = 1;
    cem_cookie *cookie;

    token = apr_strtok(apr_pstrdup(r->pool, header), ";", &next);
    if (token == NULL) return NULL;
    
    cookie = (cem_cookie *)apr_pcalloc(r->pool, sizeof(cem_cookie));
    cookie->secure = 0;
    cookie->http_only = 0;

    do {
        token = trim_spaces(token);
        if (! strlen(token)) continue;

        // The first token is the cookie itself
        if (first) {
            cookie->name  = cookie_get_name(r, token);
            cookie->value = cookie_get_value(r, token);

            first = 0;
            continue;
        }

        char *name = cookie_get_name(r, token);
        char *p = name;
        for ( ; *p; ++p) *p = apr_tolower(*p);

        if (! strcmp(name, "secure"))
            cookie->secure = 1;
        else if (! strcmp(name, "httponly"))
            cookie->http_only = 1;
        else if (! strcmp(name, "domain"))
            cookie->domain = cookie_get_value(r, token);
        else if (! strcmp(name, "path"))
            cookie->path = cookie_get_value(r, token);

    } while ((token = apr_strtok(NULL, ";", &next)) != NULL);

    return cookie;
}


/**
 * Create configuration for directory. By default, disable the engine.
 */
static void *cem_create_directory_config(apr_pool_t *pool, char *context)
{
    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, pool, "cem_create_directory_config(%s)", context);

    cem_directory_conf *conf;
    conf = (cem_directory_conf *)apr_pcalloc(pool, sizeof(cem_directory_conf));

    context = context ? context : "(undefined context)";

    if (conf) {
        conf->state   = ENGINE_DISABLED;
        conf->context = apr_pstrdup(pool, context);
    }

    return (void *)conf;
}

static void *cem_merge_directory_config(apr_pool_t *pool, void *_parent, void *_child)
{
    cem_directory_conf *parent = (cem_directory_conf *) _parent;
    cem_directory_conf *child  = (cem_directory_conf *) _child;
    cem_directory_conf *conf   = (cem_directory_conf *) cem_create_directory_config(pool, "Merged configuration");

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, pool, "cem_merge_directory_config(%s, %s)", parent->context, child->context);

    /* Merge configurations */
    conf->state   = (child->state == 0) ? parent->state : child->state ;
    conf->context = apr_pstrdup(pool, strlen(child->context) ? child->context : parent->context);

    return (void *)conf;
}


/**
 * Create configuration for the server. By default, disable the engine.
 */
static void *config_server_create(apr_pool_t *p, server_rec *s)
{
    cem_server_conf *conf;
    conf = (cem_server_conf *)apr_pcalloc(p, sizeof(cem_server_conf));

    if (conf) {
        conf->state = ENGINE_DISABLED;
    }

    return (void *)conf;
}

/**
 * Handler for the "CookiesEncapsulation" directive.
 *
 * <virtualhost ...>
 *     <location /test>
 *         CookiesEncapsulation On
 *     </location>
 * </virtualhost>
 */
const char *cem_set_enabled(cmd_parms *cmd, void *in_dconf, int flag)
{
    cem_server_conf    *sconf;
    cem_directory_conf *dconf = in_dconf;

    // Get server configuration
    sconf = ap_get_module_config(cmd->server->module_config, &mod_cookies_encapsulation_module);

    /* server command? set both global scope and base directory scope */
    if (cmd->path == NULL) {
        sconf->state     = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
        sconf->state_set = 1;
        dconf->state     = sconf->state;
        dconf->state_set = 1;
    }
    /* directory command? set directory scope only */
    else {
        dconf->state     = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
        dconf->state_set = 1;
    }

    return NULL;
}



static int parse_set_cookie_header(void *rec, const char *key, const char *val)
{
    ap_filter_t *f = (ap_filter_t *) rec;
    cem_cookie *cookie = parse_set_cookie(f->r, val);

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, f->c->pool, "Set my cookie(name:%s; value:%s; secure:%d; httponly:%d",
            cookie->name,
            cookie->value,
            cookie->secure,
            cookie->http_only);

    return TRUE;
}

apr_status_t cookies_output_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
    // Execute filter only on initial request
    if (! ap_is_initial_req(f->r)) {
        return ap_pass_brigade(f->next, bb);
    }

    ap_log_perror(APLOG_MARK, APLOG_DEBUG, APLOG_NOERRNO, f->c->pool,
            "Replacing `Set-Cookie` headers by session id.");

    // List every 'Set-Cookie' headers
    apr_table_do(parse_set_cookie_header, f, f->r->headers_out, "Set-Cookie", NULL);

    // Replace 'Set-Cookie' with session ID 
    apr_table_set(f->r->headers_out, "Set-Cookie", "ad12e98754bc");

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static void cookies_insert_output_filter(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Insert filter without handler for %s", r->hostname);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "TODO: test module config");

    // Add module if specified in config
    ap_add_output_filter(COOKIES_OUTPUT_FILTER_NAME,  NULL, r, r->connection);
}

/**
 * Replace Cookie header by token.
 */
static int cookies_input_handler(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Request %s", r->hostname);
    apr_table_set(r->headers_in, "Cookie", "truc=cookiereplacement");
    return DECLINED;
}

static void cem_register_hooks(apr_pool_t *p)
{
    ap_hook_insert_filter(cookies_insert_output_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter(COOKIES_OUTPUT_FILTER_NAME, cookies_output_filter, NULL, AP_FTYPE_RESOURCE);

    ap_hook_handler(cookies_input_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

static const command_rec cem_directives[] =
{
    AP_INIT_FLAG("CookiesEncapsulation", cem_set_enabled, NULL, OR_FILEINFO,
            "On or Off to enable or disable (default) cookies encapsulation."),
    { NULL }
};


module AP_MODULE_DECLARE_DATA mod_cookies_encapsulation_module =
{
    STANDARD20_MODULE_STUFF,
    cem_create_directory_config,
    cem_merge_directory_config,
    config_server_create,
    NULL,
    cem_directives,
    cem_register_hooks
};
