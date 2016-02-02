#include "mod_psm_cookies.h"

json_t *cookie_tojson(psm_cookie *cookie)
{
    json_t *root = json_object();

    json_object_set_new(root, "name", json_string(cookie->name));
    json_object_set_new(root, "value", json_string(cookie->value));

    return root;
}

json_t *cookies_tojson(apr_array_header_t *cookies)
{
    int i;
    json_t *root = json_array();

    for (i = 0; i < cookies->nelts; i++) {
        psm_cookie *cookie = ((psm_cookie **)cookies->elts)[i];
        json_array_append(root, cookie_tojson(cookie));
    }

    return root;
}

char *cookie_serialize(apr_pool_t *p, psm_cookie *cookie)
{
    json_t *root = cookie_tojson(cookie);
    char *tmp    = json_dumps(root, 0);
    char *buffer = apr_pstrdup(p, tmp);

    // Free JSON resources
    json_decref(root);
    free(tmp);

    return buffer;
}

char *cookies_serialize(apr_pool_t *p, apr_array_header_t *cookies)
{

    json_t *root = cookies_tojson(cookies);
    char *tmp    = json_dumps(root, 0);
    char *buffer = apr_pstrdup(p, tmp);

    // Free JSON array
    json_decref(root);
    free(tmp);

    return buffer;
}

psm_cookie *cookie_fromjson(apr_pool_t *p, json_t *root)
{
    psm_cookie *cookie;
    json_t *name;
    json_t *value;

    // Initialize cookie structure
    cookie = (psm_cookie *)apr_pcalloc(p, sizeof(psm_cookie));

    // Fetch cookie name
    name = json_object_get(root, "name");
    if ((! name) || (json_typeof(name) != JSON_STRING)) return NULL;
    cookie->name = apr_pstrdup(p, json_string_value(name));

    // Fetch cookie value
    value = json_object_get(root, "value");
    if ((! value) || (json_typeof(value) != JSON_STRING)) return NULL;
    cookie->value = apr_pstrdup(p, json_string_value(value));

    return cookie;
}

int cookies_unserialize(apr_pool_t *p, apr_array_header_t *cookies, char *buffer)
{
    unsigned int i;
    size_t size;
    json_t *root;
    json_error_t error;

    // Load and parse JSON string
    root = json_loads(buffer, 0, &error);

    // Validate JSON object 
    if ((! root) || (json_typeof(root) != JSON_ARRAY)) return DONE;

    // Get number of cookies
    size = json_array_size(root);

    for (i = 0; i < size; i++) {
        *(psm_cookie**)apr_array_push(cookies) = cookie_fromjson(p, json_array_get(root, i));
    }

    json_decref(root);

    return OK;
}

char *cookie_get_name(apr_pool_t *p, const char *header)
{
    char *next;
    return apr_strtok(apr_pstrdup(p, header), "=", &next);
}

char *cookie_get_value(apr_pool_t *p, const char *header)
{
    char *next;
    apr_strtok(apr_pstrdup(p, header), "=", &next);
    return next;
}

/**
 * Parse a Cookie header value to extract a psm_cookie struct.
 */
apr_array_header_t *parse_cookie(apr_pool_t *p, const char *header)
{
    char *next;
    char *token;
    apr_array_header_t *cookies;

    cookies = apr_array_make(p, PSM_ARRAY_INIT_SZ, sizeof(psm_cookie *));

    token = apr_strtok(apr_pstrdup(p, header), ";", &next);
    if (token == NULL) return NULL;


    do {
        psm_cookie *cookie;

        // Filter the token
        token = trim_spaces(token);
        if (! strlen(token)) continue;

        // Initialize the cookie object
        cookie = (psm_cookie *)apr_pcalloc(p, sizeof(psm_cookie));
        cookie->name  = cookie_get_name(p, token);
        cookie->value = cookie_get_value(p, token);

        // Add the cookie to the array
        *(psm_cookie**)apr_array_push(cookies) = cookie;
    } while ((token = apr_strtok(NULL, ";", &next)) != NULL);

    return cookies;
}

psm_cookie *parse_set_cookie(apr_pool_t *p, const char *header)
{
    char *next;
    char *token;
    unsigned int first = 1;
    psm_cookie *cookie;

    token = apr_strtok(apr_pstrdup(p, header), ";", &next);
    if (token == NULL) return NULL;

    cookie = (psm_cookie *)apr_pcalloc(p, sizeof(psm_cookie));
    cookie->secure = 0;
    cookie->http_only = 0;

    token = trim_spaces(token);
    if (! strlen(token)) return NULL;

    cookie->name  = cookie_get_name(p, token);
    cookie->value = cookie_get_value(p, token);

    while ((token = apr_strtok(NULL, ";", &next)) != NULL) {
        char *name;

        token = trim_spaces(token);
        if (! strlen(token)) continue;

        name = cookie_get_name(p, token);
        if (! strcasecmp(name, "secure"))
            cookie->secure = 1;
        else if (! strcasecmp(name, "httponly"))
            cookie->http_only = 1;
        else if (! strcasecmp(name, "domain"))
            cookie->domain = cookie_get_value(p, token);
        else if (! strcasecmp(name, "path"))
            cookie->path = cookie_get_value(p, token);
    }

    return cookie;
}

void psm_table_set_cookie(apr_table_t *t, psm_cookie *cookie)
{
    apr_pool_t *pool;
    apr_pool_create(&pool, NULL);
    const char *header = apr_pstrcat(pool, cookie->name, "=", cookie->value, NULL);
    apr_table_set(t, "Set-Cookie", header);
    apr_pool_destroy(pool);
}