/* Copyright (C) 2016 by Raphael Medaer
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file mod_psm.h
 * @author Raphael Medaer
 * @date 2 Feb 2016
 * @brief File containing core of Private State Manager module for Apache2.
 *
 * This file contains the base code of the module:
 *
 *  - Declaration of the Apache2 module.
 *  - Handler for incoming requests.
 *  - Filter for outgoing content of the requests.
 *  - Configuration initialization functions.
 *  - Handlers for Apache directives.
 */

#ifndef MOD_PSM_H
#define MOD_PSM_H

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include <apr_general.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include <apr_lib.h>

#include <util_filter.h>

#include "mod_psm_utils.h"
#include "mod_psm_cookies.h"
#include "mod_psm_driver_redis.h"

#define PSM_ENGINE_ENABLED 1
#define PSM_ENGINE_DISABLED 0
#define PSM_OUTPUT_FILTER_NAME "psm_output_filter"
#define PSM_USERDATA_KEY "psm_post_config"
#define PSM_TOKEN_NAME "t"
#define PSM_TOKEN_LENGTH 32

module AP_MODULE_DECLARE_DATA psm_module;

typedef struct psm_driver {
    int (*initialize)(apr_pool_t *p, apr_table_t *args, void **data);
    int (*save_cookies)(apr_pool_t *p, void *data, apr_array_header_t *cookies, char *token);
    int (*fetch_cookies)(apr_pool_t *p, void *data, apr_array_header_t *cookies, char *token);
    int (*destroy)();
    apr_table_t *params;
    void **data;
} psm_driver;

typedef struct psm_server_conf {
    int                state;
    unsigned int       state_set:1;
    struct psm_driver *driver;
} psm_server_conf;

typedef struct psm_directory_conf {
    int          state;
    unsigned int state_set:1;
} psm_directory_conf;

typedef struct psm_request_vars {
    char *token;
} psm_request_vars;

typedef struct psm_filter_data {
    request_rec *request;
    apr_array_header_t *cookies;
} psm_filter_data;

apr_status_t psm_output_filter(ap_filter_t* f, apr_bucket_brigade* bb);
void psm_insert_output_filter(request_rec *r);
int psm_input_handler(request_rec *r);

void *psm_config_directory_create(apr_pool_t *pool, char *context);
void *psm_config_directory_merge(apr_pool_t *pool, void *_parent, void *_child);
void *psm_config_server_create(apr_pool_t *p, server_rec *s);
void *psm_config_server_merge(apr_pool_t *pool, void *_parent, void *_child);
int psm_check_configuration(psm_server_conf *conf);
int psm_initialize(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
const char *psm_set_enabled(cmd_parms *cmd, void *in_dconf, int flag);
const char *psm_set_driver(cmd_parms *cmd, void *cfg, const char *arg);
const char *psm_set_driver_params(cmd_parms *cmd, void *cfg, const char *arg);
void psm_hooks_register(apr_pool_t *p);
int psm_parse_set_cookie(void *_data, const char *key, const char *value);
void psm_map_cookies(request_rec *r, psm_driver *driver);

#endif /* MOD_PSM_H */
