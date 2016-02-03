/**
 * @file mod_psm.c
 * @author Raphael Medaer
 * @date 2 Feb 2016
 * @license See header file (mod_psm.h)
 * @doc See header file (mod_psm.h)
 */
#include "mod_psm.h"


// Parse 'Set-Cookie header' and fill-in the cookies apr_array
int psm_parse_set_cookie(void *_data, const char *key, const char *value)
{
    psm_filter_data *data = (psm_filter_data *)_data;
    psm_cookie *cookie =  parse_set_cookie(data->request->pool, value);

    *(psm_cookie**)apr_array_push(data->cookies) = cookie;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, data->request,
        "Outgoing cookie %s: \"%s\" (secure:%d, httponly:%d)",
        cookie->name,
        cookie->value,
        cookie->secure,
        cookie->http_only);

    return TRUE;
}

// Filter outgoing content of requests and replace `Set-Cookie` headers by a
// single token (defined in input handler).
// The upstream cookies will be stored through the configured driver.
apr_status_t psm_output_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
    psm_request_vars *vars;
    psm_filter_data *data;
    psm_server_conf *conf;

    // Fetch configuration of the server
    conf = (psm_server_conf*) ap_get_module_config(f->r->server->module_config, &psm_module);

    // Execute filter only on initial request
    if (! ap_is_initial_req(f->r)) return ap_pass_brigade(f->next, bb);

    // Fetch configuration created by `psm_input_handler`
    vars = (psm_request_vars *)ap_get_module_config(f->r->request_config, &psm_module);
    if (vars == NULL) {
        // TODO GENERATE ERROR: 500
    }

    // Parse and list every 'Set-Cookie' headers
    data = (psm_filter_data *)apr_palloc(f->r->pool, sizeof(psm_filter_data));
    data->request = f->r;
    data->cookies = apr_array_make(f->r->pool, PSM_ARRAY_INIT_SZ, sizeof(psm_cookie *));
    apr_table_do(psm_parse_set_cookie, data, f->r->headers_out, HEADER_SET_COOKIE, NULL);

    // Let the driver save cookies
    conf->driver->save_cookies(f->r->pool, *conf->driver->data, data->cookies, vars->token);

    // Replace outgoing "Set-Cookie" header by session token
    psm_write_set_cookie(f->r->headers_out, &(psm_cookie) {
        PSM_TOKEN_NAME,
        vars->token,
    });

    // Remove this filter and go to next one
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

// Insert output filter add the beginning of the request. Because there is not
// any handler on outgoing content, we are using filter to replace cookies.
// The filter is added only if the directive has been set.
void psm_insert_output_filter(request_rec *r)
{
    psm_directory_conf *conf;

    conf = (psm_directory_conf*) ap_get_module_config(r->per_dir_config, &psm_module);
    if (! conf->state) return;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Enabling psm output filter");
    ap_add_output_filter(PSM_OUTPUT_FILTER_NAME,  NULL, r, r->connection);
}

// Handle input request before executing content generation. This will execute
// cookies mapping process if and only if the directory flag is set.
int psm_input_handler(request_rec *r)
{
    psm_server_conf *s_conf;
    psm_directory_conf *d_conf;

    // Fetch directory configuration. If the flag is not set, we not have to
    // execute the cookies mapping process
    d_conf = (psm_directory_conf*) ap_get_module_config(r->per_dir_config, &psm_module);
    if (! d_conf->state) return DECLINED;

    // Fetch server configuration.
    s_conf = (psm_server_conf*) ap_get_module_config(r->server->module_config, &psm_module);

    // Execute the mapping
    psm_map_cookies(r, s_conf->driver);
    return DECLINED;
}

// Replace the incoming token from the cookies to the data set from driver
// database. If the token is not set or doesn't exist, it will generate a new
// one and set it in request variables for the output filter.
//
// TODO: It should be useful to put the token into a special header or cookie.
void psm_map_cookies(request_rec *r, psm_driver *driver)
{
    const char *header;
    char *token;
    psm_request_vars *vars;
    unsigned int found = 0;

    // Fetch configuration of the server
    vars = (psm_request_vars *) apr_palloc(r->pool, sizeof(psm_request_vars));

    // Look at `Cookie` header to get private state cookie
    header = apr_table_get(r->headers_in, HEADER_COOKIE);
    if (header != NULL) {
        int i;
        apr_array_header_t *cookies;

        // Parse incoming cookies
        cookies = parse_cookie(r->pool, header);

        // Test if the private state cookie is set and contains a token
        for (i = 0; i < cookies->nelts && ! found; i++) {
            psm_cookie *cookie = ((psm_cookie **)cookies->elts)[i];

            if (! strcasecmp(cookie->name, PSM_TOKEN_NAME) && strlen(cookie->value)) {
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                    "Private token detected: %s", cookie->value);

                vars->token = apr_pstrdup(r->pool, cookie->value);
                found = 1;
            }
        }
    }

    // Try to retrieve cookies from the driver if we found the private state cookie token
    if (found) {
        apr_array_header_t *cookies;

        // Initialize Apache array with the good size
        cookies = apr_array_make(r->pool, PSM_ARRAY_INIT_SZ, sizeof(psm_cookie *));

        // Fetch "data" cookies from the driver (aka db) and write them
        if (driver->fetch_cookies(r->pool, *driver->data, cookies, vars->token) == OK) {
            psm_write_cookie(r->headers_in, cookies);
        }

        // If we didn't find it, trigger the token generation
        else {
            found = 0;
        }
    }

    // Re-check in case of fetch_cookies function failed
    if (! found) {
        // Generate a random token
        vars->token = generate_token(r->pool, PSM_TOKEN_LENGTH);

        // Unset incoming cookies
        apr_table_unset(r->headers_in, HEADER_COOKIE);

        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
            "Not any private token found. New token set: %s", vars->token);
    }

    // Set variables of this request for the output filter
    // TODO is it mandatory to set when `vars` is a pointer ?
    ap_set_module_config(r->request_config, &psm_module, vars);
}

// Create directory configuration.
void *psm_config_directory_create(apr_pool_t *pool, char *context)
{
    psm_directory_conf *conf;

    conf = (psm_directory_conf *)apr_pcalloc(pool, sizeof(psm_directory_conf));
    if (conf) {
        conf->state = PSM_ENGINE_DISABLED;
    }

    return (void *)conf;
}

// Merge two directory configuations. It will enable the filtering depending the
// child configuration.
void *psm_config_directory_merge(apr_pool_t *pool, void *_parent, void *_child)
{
    psm_directory_conf *parent;
    psm_directory_conf *child;
    psm_directory_conf *conf;

    parent = (psm_directory_conf *) _parent;
    child  = (psm_directory_conf *) _child;
    conf   = (psm_directory_conf *) psm_config_directory_create(pool, "Merged configuration");

    // Merge configurations
    conf->state = (child->state == 0) ? parent->state : child->state ;

    return (void *)conf;
}

// Create server configuration. By default, the filtering is disabled.
void *psm_config_server_create(apr_pool_t *p, server_rec *s)
{
    psm_server_conf *conf;

    conf = (psm_server_conf *)apr_pcalloc(p, sizeof(psm_server_conf));
    if (! conf) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p,
            "Failed to create server configuration; memory allocation failure.");
        return NULL;
    }

    conf->state = PSM_ENGINE_DISABLED;
    conf->driver = (psm_driver *)apr_pcalloc(p, sizeof(psm_driver));
    conf->driver->params = apr_table_make(p, 8);

    return (void *)conf;
}

// Merge two server configurations. It copy the driver information and set the
// module state depending the child configuration.
void *psm_config_server_merge(apr_pool_t *p, void *_parent, void *_child)
{
    psm_server_conf *parent;
    psm_server_conf *child;
    psm_server_conf *conf;

    parent = (psm_server_conf *) _parent;
    child  = (psm_server_conf *) _child;
    conf   = (psm_server_conf *)apr_pcalloc(p, sizeof(psm_server_conf));

    // Merge configurations
    conf->state = (child->state == 0) ? parent->state : child->state ;
    conf->driver = (child->driver) ? parent->driver : child->driver;

    return (void *)conf;
}

// Check module configuration. Ensure that every callbacks of selected driver
// are set.
//
// TODO: Even it should may create an empty default callback.
int psm_check_configuration(psm_server_conf *conf)
{
    return conf->driver->initialize
        && conf->driver->save_cookies
        && conf->driver->fetch_cookies
        && conf->driver->destroy;
}

// Initialize the module (especially its driver). This function is called after
// the configuration step.
int psm_initialize(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    void *data = NULL;
    psm_server_conf *conf;

    // Be sure this is the second config iteration (see Apache doc)
    apr_pool_userdata_get(&data, PSM_USERDATA_KEY, s->process->pool);
    if (data == NULL) {
        apr_pool_userdata_set(
            (const void *)1,
            PSM_USERDATA_KEY,
            apr_pool_cleanup_null,
            s->process->pool);

        return OK;
    }

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p,
        "Initializing Private State Manager module...");

    // Get module configuration
    conf = ap_get_module_config(s->module_config, &psm_module);

    // Check driver configuration
    if (! psm_check_configuration(conf)) return DONE;

    // Initialize the selected driver
    conf->driver->data = (void *)apr_pcalloc(p, sizeof(void *));
    if (conf->driver->initialize(p, conf->driver->params, conf->driver->data) != OK) {
        return DONE;
    }

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p,
        "Private State Manager module initialized !");

    return OK;
}

// Enable/disable the module depending the flag. This handler is used both for
// directory and server configuration.
const char *psm_set_enabled(cmd_parms *cmd, void *in_dconf, int flag)
{
    psm_server_conf    *sconf;
    psm_directory_conf *dconf = (psm_directory_conf *)in_dconf;

    // Get server configuration
    sconf = ap_get_module_config(cmd->server->module_config, &psm_module);

    // If it's a server command, set both global scope and base directory scope
    if (cmd->path == NULL) {
        sconf->state     = (flag ? PSM_ENGINE_ENABLED : PSM_ENGINE_DISABLED);
        sconf->state_set = 1;
        dconf->state     = sconf->state;
        dconf->state_set = 1;
    }

    // If it's a directory command, set directory scope only
    else {
        dconf->state     = (flag ? PSM_ENGINE_ENABLED : PSM_ENGINE_DISABLED);
        dconf->state_set = 1;
    }

    return NULL;
}

// Set the driver to use.
const char *psm_set_driver(cmd_parms *cmd, void *cfg, const char *arg)
{
    psm_server_conf *conf;

    // This directive should be only used in global scope.
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    // Set the callbacks depending driver name
    conf = (psm_server_conf*)ap_get_module_config(cmd->server->module_config, &psm_module);
    if (! strcasecmp(arg, "redis")) {
        conf->driver->initialize    = psm_redis_initialize;
        conf->driver->save_cookies  = psm_redis_save_cookies;
        conf->driver->fetch_cookies = psm_redis_fetch_cookies;
        conf->driver->destroy       = psm_redis_destroy;
    }

    // If the driver is unknown return an error
    else {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, cmd->pool, "Unknown driver type \"%s\"", arg);
        return "Unknown psm driver.";
    }

    return NULL;
}

// Parse the driver parameters one-by-one and put them into the global server
// configuration.
const char *psm_set_driver_params(cmd_parms *cmd, void *cfg, const char *arg)
{
    psm_server_conf *conf = (psm_server_conf*)ap_get_module_config(
            cmd->server->module_config, &psm_module);

    char *value;
    char *key = apr_strtok(apr_pstrdup(cmd->pool, arg), "=", &value);

    apr_table_set(conf->driver->params, key, value);

    return NULL;
}

// Register every module handlers
void psm_hooks_register(apr_pool_t *p)
{
    // after the configuration ...
    ap_hook_post_config(psm_initialize, NULL, NULL, APR_HOOK_LAST);

    // before each request processing ...
    ap_hook_handler(psm_input_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);

    // register filter and add it in a insert_filter handler
    ap_register_output_filter(PSM_OUTPUT_FILTER_NAME, psm_output_filter, NULL, AP_FTYPE_RESOURCE);
    ap_hook_insert_filter(psm_insert_output_filter, NULL, NULL, APR_HOOK_MIDDLE);
}

// Module's directives
const command_rec psm_directives[] =
{
    AP_INIT_FLAG("PrivateStateManager", psm_set_enabled, NULL, OR_FILEINFO, "On or Off to enable or disable (default) the module."),
    AP_INIT_TAKE1("PrivateStateManagerDriver", psm_set_driver, NULL, RSRC_CONF, "Driver (name) to use for private state storage."),
    AP_INIT_ITERATE("PrivateStateManagerDriverParams", psm_set_driver_params, NULL, RSRC_CONF, "Driver proprietary configuration."),
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
