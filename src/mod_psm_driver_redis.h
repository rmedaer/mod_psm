#ifndef MOD_PSM_DRIVER_REDIS_H
#define MOD_PSM_DRIVER_REDIS_H

#include <hiredis/hiredis.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <apr_proc_mutex.h>
#include <util_filter.h>

#include "mod_psm_cookies.h"

#define PSM_REDIS_MAX_RETRIES 3
#define PSM_REDIS_MUTEX "psm_redis_mutex"

int psm_redis_initialize(apr_pool_t *p, apr_table_t *args, void **data);
int psm_redis_save_cookies(apr_pool_t *p, void *data, apr_array_header_t *cookies, char *token);
int psm_redis_fetch_cookies(apr_pool_t *p, void *data, apr_array_header_t *cookies, char *token);
int psm_redis_destroy();


#endif /* MOD_PSM_DRIVER_REDIS_H */
