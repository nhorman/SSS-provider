#include <openssl/core.h> 
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>

static int sss_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME); 
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL SSS Provider"))
        return 0;
    return 1;
}

OSSL_DISPATCH provider_table[] = { 
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))sss_get_params },
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



