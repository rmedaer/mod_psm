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

#define ENGINE_ENABLED 1
#define ENGINE_DISABLED 0
#define COOKIES_OUTPUT_FILTER_NAME "cookies_encapsulation_output_filter"

module AP_MODULE_DECLARE_DATA mod_cookies_encapsulation_module;

typedef int (cem_driver_initialize)();
typedef int (cem_driver_save_cookies)(char *id, char *data);
typedef int (cem_driver_fetch_cookies)(char *id);
typedef int (cem_driver_destroy)();

typedef struct cem_driver {
    cem_driver_initialize    *init;
    cem_driver_save_cookies  *set;
    cem_driver_fetch_cookies *get;
    cem_driver_destroy       *destroy;
} cem_driver;

typedef struct {
    int          state;
    unsigned int state_set:1;
    char        *context;
} cem_server_conf;

typedef struct {
    int          state;
    unsigned int state_set:1;
    char        *context;
} cem_directory_conf;


typedef struct cem_cookie {
    char      *name;
    char      *value;
    char      *path;
    char      *domain;
    int        expires;
    int        max_age;
    short int  secure;
    short int  http_only;
    char      *raw;
} cem_cookie;

typedef struct cem_cookie_entry {
    struct cem_cookie       *v;
    struct cem_cookie_entry *next;
} cem_cookie_entry;


static char *trim_spaces(char *str);

static char *cookie_get_name(request_rec *r, const char *header);

static char *cookie_get_value(request_rec *r, const char *header);

static cem_cookie_entry *parse_cookie(request_rec *r, const char *header);

static cem_cookie *parse_set_cookie(request_rec * r, const char *header);

static void *cem_create_directory_config(apr_pool_t *pool, char *context);

static void *cem_merge_directory_config(apr_pool_t *pool, void *_parent, void *_child);

static void *config_server_create(apr_pool_t *p, server_rec *s);

const char *cem_set_enabled(cmd_parms *cmd, void *in_dconf, int flag);

static int parse_set_cookie_header(void *rec, const char *key, const char *val);

apr_status_t cookies_output_filter(ap_filter_t* f, apr_bucket_brigade* bb);

static void cookies_insert_output_filter(request_rec *r);

static int cookies_input_handler(request_rec *r);

static void cem_register_hooks(apr_pool_t *p);
