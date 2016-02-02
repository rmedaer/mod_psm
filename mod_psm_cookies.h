#ifndef MOD_PSM_COOKIES_H
#define MOD_PSM_COOKIES_H

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include <jansson.h>

#include "mod_psm_utils.h"

#define PSM_ARRAY_INIT_SZ 2

typedef struct psm_cookie {
    char      *name;
    char      *value;
    char      *path;
    char      *domain;
    int        expires;
    int        max_age;
    short int  secure;
    short int  http_only;
} psm_cookie;

// JSON conversion functions
json_t *cookie_tojson(psm_cookie *cookie);
json_t *cookies_tojson(apr_array_header_t *cookies);
psm_cookie *cookie_fromjson(apr_pool_t *p, json_t *root);

// Cookie serialization functions
char *cookie_serialize(apr_pool_t *p, psm_cookie *cookie);
char *cookies_serialize(apr_pool_t *p, apr_array_header_t *cookies);
int cookies_unserialize(apr_pool_t *p, apr_array_header_t *cookies, char *buffer);

// HTTP parser functions
char *cookie_get_name(apr_pool_t *p, const char *header);
char *cookie_get_value(apr_pool_t *p, const char *header);
apr_array_header_t *parse_cookie(apr_pool_t *p, const char *header);
psm_cookie *parse_set_cookie(apr_pool_t *p, const char *header);
void psm_table_set_cookie(apr_table_t *t, psm_cookie *cookie);


#endif /* MOD_PSM_COOKIES_H */
