#include "mod_psm_utils.h"

char *trim_spaces(char *str)
{
    char *out;

    // Trim leading space
    while(apr_isspace(*str)) str++;

    if(*str == '\0')  // All spaces?
        return str;

    // Trim trailing space
    out = str + strlen(str) - 1;

    while(out > str && apr_isspace(*out)) out--;

    // Write new null terminator
    *(out + 1) = '\0';

    return str;
}

apr_status_t seed_rand(void)
{
    int seed = 0;
    apr_status_t status;

#if APR_HAS_RANDOM
    status = apr_generate_random_bytes((unsigned char*) &seed, sizeof(seed));
#else
#error APR random number support is missing; you probably need to install the truerand library.
#endif

    if (status != APR_SUCCESS) {
        return status;
    }

    srand(seed);
    return status;
}

char *generate_token(apr_pool_t *pool, size_t len)
{
    apr_status_t status;
    char *token = NULL;

    if (len <= 0) return NULL;

    if (seed_rand() != APR_SUCCESS) return NULL;

    token = (char *)apr_pcalloc(pool, sizeof(char) * (len + 1));
    if (token == NULL) return NULL;

    for (int n = 0; n < len; n++) {
        int key = rand() % (int)(sizeof(TOKEN_CHARSET) - 1);
        token[n] = TOKEN_CHARSET[key];
    }

    token[len] = '\0';
    return token;
}
