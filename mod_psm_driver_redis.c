#include "mod_psm_driver_redis.h"


typedef struct psm_redis_data {
    redisContext *context;
    apr_proc_mutex_t *mutex;
} psm_redis_data;

int psm_redis_initialize(apr_pool_t *p, apr_table_t *args, void **_data)
{
    psm_redis_data **data = (psm_redis_data **)_data;
    redisContext *context;
    const char *host;
    const char *_port;
    int port;

    if (! (host = apr_table_get(args, "host"))) {
        host = "127.0.0.1";
    }

    if (! (_port = apr_table_get(args, "port"))) {
        _port = "6379";
    }
    port = atoi(_port);

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "psm_redis_initialize %s:%d", host, port);

    context = redisConnect(host, port);
    if (context != NULL && context->err) {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Failed to establish connection with server: %s", context->errstr);
        return DONE;
    }

    *data = (void *)apr_pcalloc(p, sizeof(psm_redis_data));
    (*data)->context = context;
    if (apr_proc_mutex_create(&(*data)->mutex, "test", APR_LOCK_PROC_PTHREAD, p) != APR_SUCCESS) return DONE;

    return OK;
}

int psm_redis_save_cookies(apr_pool_t *p, void *_data, apr_array_header_t *cookies, char *token)
{
    char *buffer;
    int status = OK;
    psm_redis_data *data = (psm_redis_data *)_data;

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Attempt to save token \"%s\" with %d cookies", token, cookies->nelts);

    buffer = cookies_serialize(p, cookies);

    if (apr_proc_mutex_lock(data->mutex) != APR_SUCCESS) return DONE;


    redisReply *reply = redisCommand(data->context, "SETEX %s 10 %s", token, buffer);
    if (reply->type == REDIS_REPLY_ERROR) {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Failed to execute request: %d", data->context->err);

        status = DONE;
    }

    // Free and release..
    freeReplyObject(reply);

    if (apr_proc_mutex_unlock(data->mutex) != APR_SUCCESS) return DONE;

    return status;
}

int psm_redis_fetch_cookies(apr_pool_t *p, void *_data, apr_array_header_t *cookies, char *token)
{
    int status = OK;
    psm_redis_data *data = (psm_redis_data *)_data;

    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Attempt to fetch cookies from token \"%s\"", token);

    if (apr_proc_mutex_lock(data->mutex) != APR_SUCCESS) return DONE;

    redisReply *reply = redisCommand(data->context, "GET %s", token);
    if (reply->type != REDIS_REPLY_STRING) {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Failed to execute request: %d", data->context->err);
        status = DONE;
    } else {
        status = cookies_unserialize(p, cookies, reply->str);
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "[redis] Data fetched: %d cookies", cookies->nelts);
    }

    // Free and release..
    freeReplyObject(reply);

    if (apr_proc_mutex_unlock(data->mutex) != APR_SUCCESS) return DONE;

    return status;
}


int psm_redis_destroy()
{
    return OK;
}
