#include "mod_psm_driver_redis.h"


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
    char *buffer;
    int status = OK;
    int retry = 0;
    psm_redis_data *data = (psm_redis_data *)_data;

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Attempt to save token \"%s\" with %d cookies", token, cookies->nelts);

    buffer = cookies_serialize(p, cookies);

    if (apr_proc_mutex_lock(data->mutex) != APR_SUCCESS) return DONE;

    // On error, trigger reconnection and retry
    redisReply *reply;
    do {
        reply = redisCommand(data->context, "SETEX %s %d %s", token, data->expire, buffer);
        if (! reply) {
            ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Attempt to reconnect Redis server");
            if (redisReconnect(data->context) == REDIS_OK) {
                ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Reconnected.");
            }
        }
    } while (! reply && retry++ < PSM_REDIS_MAX_RETRIES);

    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Failed to execute request: %s", data->context->errstr);

        status = DONE;
    }

    // Free and release..
    if (reply) freeReplyObject(reply);

    if (apr_proc_mutex_unlock(data->mutex) != APR_SUCCESS) return DONE;

    return status;
}

int psm_redis_fetch_cookies(apr_pool_t *p, void *_data, apr_array_header_t *cookies, char *token)
{
    int status = OK;
    int retry = 0;
    psm_redis_data *data = (psm_redis_data *)_data;

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Attempt to fetch cookies from token \"%s\"", token);

    if (apr_proc_mutex_lock(data->mutex) != APR_SUCCESS) return DONE;

    redisReply *reply;
    do {
        reply = redisCommand(data->context, "GET %s", token);
        if (! reply) {
            ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Attempt to reconnect Redis server");
            if (redisReconnect(data->context) == REDIS_OK) {
                ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Reconnected.");
            }
        }
    } while (! reply && retry++ < PSM_REDIS_MAX_RETRIES);

    if (reply == NULL || reply->type != REDIS_REPLY_STRING) {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Failed to execute request: %d", data->context->err);
        status = DONE;
    } else {
        status = cookies_unserialize(p, cookies, reply->str);
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Data fetched: %d cookies", cookies->nelts);
    }

    // Free and release..
    if (reply) freeReplyObject(reply);

    if (apr_proc_mutex_unlock(data->mutex) != APR_SUCCESS) return DONE;

    return status;
}


int psm_redis_destroy()
{
    return OK;
}
