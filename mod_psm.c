/**
 *
 * NOTE: The internal module's logic is highly inspired from mod_rewrite for
 * configuraiton.
 *
 */


/**
 * Include core server components.
 */
#include "mod_psm.h"

int psm_parse_set_cookie(void *_data, const char *key, const char *value)
{
    psm_filter_data *data = (psm_filter_data *)_data;
    psm_cookie *cookie =  parse_set_cookie(data->request->pool, value);

#ifdef PSM_DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, data->request, "Parsing `Set-Cookie` %s: \"%s\" (secure:%d, httponly:%d)",
            cookie->name,
            cookie->value,
            cookie->secure,
            cookie->http_only);
#endif

    *(psm_cookie**)apr_array_push(data->cookies) = cookie;

    return TRUE;
}

apr_status_t psm_output_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
    psm_request_vars *vars;
    psm_filter_data *data;
    psm_server_conf *conf;

    // Fetch configuration of the server
    conf = (psm_server_conf*) ap_get_module_config(f->r->server->module_config, &psm_module);

    // Execute filter only on initial request
    if (! ap_is_initial_req(f->r)) {
        return ap_pass_brigade(f->next, bb);
    }

    // Fetch configuration created by `psm_input_handler`
    vars = (psm_request_vars *)ap_get_module_config(f->r->request_config, &psm_module);
    if (vars == NULL) {
        // TODO GENERATE ERROR: 500
    }

    // Parse and list every 'Set-Cookie' headers
    data = (psm_filter_data *)apr_palloc(f->r->pool, sizeof(psm_filter_data));
    data->request = f->r;
    data->cookies = apr_array_make(f->r->pool, PSM_ARRAY_INIT_SZ, sizeof(psm_cookie *));
    apr_table_do(psm_parse_set_cookie, data, f->r->headers_out, "Set-Cookie", NULL);

    // TODO save cookies (stored in data->cookies)
    conf->driver->save_cookies(f->r->pool, *conf->driver->data, data->cookies, vars->token);

    // Replace outgoing "Set-Cookie" header by session token
    psm_table_set_cookie(f->r->headers_out, &(psm_cookie) {
        PSM_TOKEN_NAME,
        vars->token,
    });

    // Remove this filter and go to next one
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

void psm_insert_output_filter(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Insert filter without handler for %s", r->hostname);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "TODO: test module config");

    // Add module if specified in config
    // TODO read config to know if we have to put output_filter / or not
    ap_add_output_filter(PSM_OUTPUT_FILTER_NAME,  NULL, r, r->connection);
}

/**
 * Replace Cookie header by token.
 */
int psm_input_handler(request_rec *r)
{
    const char *header;
    char *token;
    psm_request_vars *vars;
    unsigned int found = 0;
    psm_server_conf *conf;

    // Fetch configuration of the server
    conf = (psm_server_conf*) ap_get_module_config(r->server->module_config, &psm_module);

    // TODO read config to determine if we have to work or not

    vars = (psm_request_vars *) apr_palloc(r->pool, sizeof(psm_request_vars));

    header = apr_table_get(r->headers_in, "Cookie");
    if (header != NULL) {
        int i;
        apr_array_header_t *cookies;

        cookies = parse_cookie(r->pool, header);

        for (i = 0; i < cookies->nelts && ! found; i++) {
            psm_cookie *cookie = ((psm_cookie **)cookies->elts)[i];

            if (! strcasecmp(cookie->name, PSM_TOKEN_NAME)) {
#ifdef PSM_DEBUG
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Private token detected: %s=%s", cookie->name, cookie->value);
#endif
                vars->token = apr_pstrdup(r->pool, cookie->value);
                found = 1;
            }
        }
    }

    if (found) {
        apr_array_header_t *cookies;

        // Initialize Apache array with the good size
        cookies = apr_array_make(r->pool, PSM_ARRAY_INIT_SZ, sizeof(psm_cookie *));

        if (conf->driver->fetch_cookies(r->pool, *conf->driver->data, cookies, vars->token) == OK) {
            char *str = "";
            int i;
            for (i = 0; i < cookies->nelts; i++) {
                psm_cookie *cookie = ((psm_cookie **)cookies->elts)[i];
                str = apr_pstrcat(r->pool, str, cookie->name, "=", cookie->value, "; ", NULL);
            }
            apr_table_set(r->headers_in, "Cookie", str);
        } else {
            found = 0;
        }
    }

    // Re-check in case of fetch_cookies function failed
    if (! found) {
        // Generate a random token
        vars->token = generate_token(r->pool, PSM_TOKEN_LENGTH);

        // Unset incoming cookies
        apr_table_unset(r->headers_in, "Cookie");

#ifdef PSM_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Not any private token found. New token set: %s", vars->token);
#endif
    }

    ap_set_module_config(r->request_config, &psm_module, vars);

    return DECLINED;
}


/**
 * Create configuration for directory. By default, it let the engine disabled.
 */
void *psm_config_directory_create(apr_pool_t *pool, char *context)
{
    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, pool, "create_directory_config(%s)", context);

    psm_directory_conf *conf;
    conf = (psm_directory_conf *)apr_pcalloc(pool, sizeof(psm_directory_conf));

    context = context ? context : "(undefined context)";

    if (conf) {
        conf->state   = PSM_ENGINE_DISABLED;
        conf->context = apr_pstrdup(pool, context);
    }

    return (void *)conf;
}

/**
 * Merge configurations.
 */
void *psm_config_directory_merge(apr_pool_t *pool, void *_parent, void *_child)
{
    psm_directory_conf *parent = (psm_directory_conf *) _parent;
    psm_directory_conf *child  = (psm_directory_conf *) _child;
    psm_directory_conf *conf   = (psm_directory_conf *) psm_config_directory_create(pool, "Merged configuration");

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, pool, "cem_merge_directory_config(%s, %s)", parent->context, child->context);

    // Merge configurations
    conf->state   = (child->state == 0) ? parent->state : child->state ;
    conf->context = apr_pstrdup(pool, strlen(child->context) ? child->context : parent->context);

    return (void *)conf;
}


/**
 * Create server configuration. By default, the module is disabled.
 */
void *psm_config_server_create(apr_pool_t *p, server_rec *s)
{
    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "config_server_create");

    psm_server_conf *conf = (psm_server_conf *)apr_pcalloc(p, sizeof(psm_server_conf));
    if (! conf) {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "config_server_create:alloc faoled");
        return NULL;
    }

    conf->state = PSM_ENGINE_DISABLED;
    conf->driver = (psm_driver *)apr_pcalloc(p, sizeof(psm_driver));
    conf->driver->params = apr_table_make(p, 8);

    return (void *)conf;
}

/**
 * Merge configurations of server.
 */
void *psm_config_server_merge(apr_pool_t *p, void *_parent, void *_child)
{
    psm_server_conf *parent = (psm_server_conf *) _parent;
    psm_server_conf *child  = (psm_server_conf *) _child;
    psm_server_conf *conf = (psm_server_conf *)apr_pcalloc(p, sizeof(psm_server_conf));

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "psm_config_server_merge");

    // Merge configurations
    conf->state = (child->state == 0) ? parent->state : child->state ;
    conf->driver = (child->driver) ? parent->driver : child->driver;

    return (void *)conf;
}

int psm_check_configuration(psm_server_conf *conf)
{
    return conf->driver->initialize
        && conf->driver->save_cookies
        && conf->driver->fetch_cookies
        && conf->driver->destroy;
}

int psm_initialize(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    void *data = NULL;
    psm_server_conf *conf;

    // Be sure this is the second config (see doc)
    apr_pool_userdata_get(&data, PSM_USERDATA_KEY, s->process->pool);
    if (data == NULL) {
        apr_pool_userdata_set((const void *)1, PSM_USERDATA_KEY, apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    conf = ap_get_module_config(s->module_config, &psm_module);

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "Initializing CEM...");

    // Check driver configuration
    if (! psm_check_configuration(conf)) return DONE;

    // Initialize the selected driver
    conf->driver->data = (void *)apr_pcalloc(p, sizeof(void *));
    conf->driver->initialize(p, conf->driver->params, conf->driver->data);
    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "Initialized %d", *conf->driver->data);
    return OK;
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
const char *psm_set_enabled(cmd_parms *cmd, void *in_dconf, int flag)
{
    psm_server_conf    *sconf;
    psm_directory_conf *dconf = in_dconf;

    // Get server configuration
    sconf = ap_get_module_config(cmd->server->module_config, &psm_module);

    /* server command? set both global scope and base directory scope */
    if (cmd->path == NULL) {
        sconf->state     = (flag ? PSM_ENGINE_ENABLED : PSM_ENGINE_DISABLED);
        sconf->state_set = 1;
        dconf->state     = sconf->state;
        dconf->state_set = 1;
    }
    /* directory command? set directory scope only */
    else {
        dconf->state     = (flag ? PSM_ENGINE_ENABLED : PSM_ENGINE_DISABLED);
        dconf->state_set = 1;
    }

    return NULL;
}

const char *psm_set_driver(cmd_parms *cmd, void *cfg, const char *arg)
{
    psm_server_conf *conf = (psm_server_conf*)ap_get_module_config(
            cmd->server->module_config, &psm_module);


    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "cem_set_driver");

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (! strcasecmp(arg, "redis")) {
        conf->driver->initialize = psm_redis_initialize;
        conf->driver->save_cookies = psm_redis_save_cookies;
        conf->driver->fetch_cookies = psm_redis_fetch_cookies;
        conf->driver->destroy = psm_redis_destroy;
    } else {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, cmd->pool, "Uknown driver type");
    }

    return NULL;
}

/**
 * Parse StateManagerDriverParams parameters one-by-one and put them into
 * the global server configuration as driver parameters.
 */
const char *psm_set_driver_params(cmd_parms *cmd, void *cfg, const char *arg)
{
    psm_server_conf *conf = (psm_server_conf*)ap_get_module_config(
            cmd->server->module_config, &psm_module);

    char *value;
    char *key = apr_strtok(apr_pstrdup(cmd->pool, arg), "=", &value);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "psm_set_driver_params(%s:%s)", key, value);
    apr_table_set(conf->driver->params, key, value);

    return NULL;
}

void psm_hooks_register(apr_pool_t *p)
{
    ap_hook_post_config(psm_initialize, NULL, NULL, APR_HOOK_LAST);

    ap_hook_insert_filter(psm_insert_output_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter(PSM_OUTPUT_FILTER_NAME, psm_output_filter, NULL, AP_FTYPE_RESOURCE);

    ap_hook_handler(psm_input_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

const command_rec psm_directives[] =
{
    AP_INIT_FLAG("PrivateStateManager", psm_set_enabled, NULL, OR_FILEINFO, "On or Off to enable or disable (default) cookies encapsulation."),
    AP_INIT_TAKE1("PrivateStateManagerDriver", psm_set_driver, NULL, RSRC_CONF, "Driver/engine to use for storage."),
    AP_INIT_ITERATE("PrivateStateManagerDriverParams", psm_set_driver_params, NULL, RSRC_CONF, "Driver path"),
    { NULL }
};


module AP_MODULE_DECLARE_DATA psm_module =
{
    STANDARD20_MODULE_STUFF,
    psm_config_directory_create,
    psm_config_directory_merge,
    psm_config_server_create,
    psm_config_server_merge,
    psm_directives,
    psm_hooks_register
};
