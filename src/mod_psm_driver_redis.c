#include "mod_psm_driver_redis.h"

#define psm_redis_command(p, context, command, ...) \
    ({ \
        int retry = 0; \
        redisReply *reply; \
        do { \
            reply = redisCommand(context, command, __VA_ARGS__); \
            if (! reply) { \
                ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Attempt to reconnect Redis server"); \
                if (redisReconnect(context) == REDIS_OK) { \
                    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Reconnected."); \
                } \
            } \
        } while (! reply && retry++ < PSM_REDIS_MAX_RETRIES); \
        reply; \
    })

#define psm_redis_lock(mutex) \
    ({ \
        if (apr_proc_mutex_lock(mutex) != APR_SUCCESS) return DONE; \
    })

#define psm_redis_unlock(mutex) \
    ({ \
        if (apr_proc_mutex_unlock(mutex) != APR_SUCCESS) return DONE; \
    })

typedef struct psm_redis_data {
    redisContext *context;
    apr_proc_mutex_t *mutex;
    int expire;
} psm_redis_data;

int psm_redis_initialize(apr_pool_t *p, apr_table_t *args, void **_data)
{
    psm_redis_data **data = (psm_redis_data **)_data;
    redisContext *context;
    const char *host;
    const char *tmp;
    int port = 6379;
    int expire = 300;

    if (! (host = apr_table_get(args, "host"))) host = "127.0.0.1";
    if (tmp = apr_table_get(args, "port")) port = atoi(tmp);
    if (tmp = apr_table_get(args, "expire")) expire = atoi(tmp);

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "psm_redis_initialize %s:%d", host, port);

    // Attempt to connect Redis server
    context = redisConnect(host, port);
    if (context == NULL) {
        // Big issue, get out of there
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Failed create Redis context");
        return DONE;
    }

    // If we cannot connect to the server we just create the context and retry later
    if (context->err) {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Failed to establish connection with server: %s", context->errstr);
    }

    *data = (void *)apr_pcalloc(p, sizeof(psm_redis_data));
    (*data)->context = context;
    (*data)->expire = expire;

    if (apr_proc_mutex_create(&(*data)->mutex, PSM_REDIS_MUTEX, APR_LOCK_PROC_PTHREAD, p) != APR_SUCCESS) return DONE;

    return OK;
}

int psm_redis_save_cookies(apr_pool_t *p, void *_data, apr_array_header_t *cookies, char *token)
{
    int i;
    char *buffer;
    int retry = 0;
    int status = OK;
    psm_redis_data *data = (psm_redis_data *)_data;

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Attempt to save token \"%s\" with %d cookies", token, cookies->nelts);

    psm_redis_lock(data->mutex);

    for (i = 0; i < cookies->nelts; i++) {
        psm_cookie *cookie;
        redisReply *reply;

        cookie = ((psm_cookie **)cookies->elts)[i];
        buffer = cookie_serialize(p, cookie);

        reply = psm_redis_command(p, data->context, "SETEX %s.%s %d %s", token, cookie->name, cookie->max_age, buffer);

        if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
            ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Failed to execute request: %s", data->context->errstr);
            status = DONE;
        }

        if (reply) freeReplyObject(reply);
    }

    psm_redis_unlock(data->mutex);

    return status;
}

int psm_redis_fetch_cookies(apr_pool_t *p, void *_data, apr_array_header_t *cookies, char *token)
{
    int status = OK;
    int retry = 0;
    psm_redis_data *data = (psm_redis_data *)_data;

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Attempt to fetch cookies from token \"%s\"", token);

    psm_redis_lock(data->mutex);

    redisReply *keys;

    keys = psm_redis_command(p, data->context, "KEYS %s.*", token);

    if (keys == NULL || keys->type != REDIS_REPLY_ARRAY) {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Failed to execute request: %d", data->context->err);
        status = DONE;
    } else if (! keys->elements) {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Not any cookies found");
        status = DONE;
    } else {
        int i;
        for (i = 0; i < keys->elements; i++) {
            redisReply *reply;

            ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, p, "[redis] Get cookie %s", keys->element[i]->str);

            reply = psm_redis_command(p, data->context, "GET %s", keys->element[i]->str);

            if (reply == NULL || reply->type != REDIS_REPLY_STRING) {
                ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Failed to execute request: %d", data->context->err);
                status = DONE;
            } else {
                psm_cookie *cookie;

                // Initialize a cookie and add it to cookies array
                cookie = (psm_cookie *)apr_pcalloc(p, sizeof(psm_cookie));
                status = cookie_unserialize(p, cookie, reply->str);
                *(psm_cookie**)apr_array_push(cookies) = cookie;
            }

            if (reply) freeReplyObject(reply);
        }
    }

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Data fetched: %d cookies", cookies->nelts);

    if (keys) freeReplyObject(keys);

    psm_redis_unlock(data->mutex);

    return status;
}


int psm_redis_destroy()
{
    return OK;
}
