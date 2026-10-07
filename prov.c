#include <openssl/core.h> 
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include "./keymgmt.h"

static int sss_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME); 
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Provider for Shamirs Secret Sharing"))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM *sss_query(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;

    if (operation_id != OSSL_OP_KEYMGMT)
        return NULL;
    return get_sss_keymgmt();
}

static const OSSL_DISPATCH provider_table[] = { 
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))sss_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))sss_query },
    {0, NULL}
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx)
{
    *out = provider_table;
    return 1;
}



