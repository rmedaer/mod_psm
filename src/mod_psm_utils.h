#ifndef MOD_PSM_UTILS_H
#define MOD_PSM_UTILS_H

#include <apr_lib.h>
#include <apr_strings.h>
#include <stdlib.h>

#define TOKEN_CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

char *trim_spaces(char *str);
apr_status_t seed_rand(void);
char *generate_token(apr_pool_t *pool, size_t len);

#endif /* MOD_PSM_UTILS_H */