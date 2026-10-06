#include <openssl/core.h> 
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>

static void *sss_new_ex(void *provctx, const OSSL_PARAM params[])
{
    return NULL;
}

static void *sss_gen_init(void *provctx, int selection,
    const OSSL_PARAM params[])
{
    return NULL;
}

static int sss_gen_set_template(void *genctx, void *templ)
{
    return 0;
}

static int sss_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    return 0;
}

static const OSSL_PARAM *sss_gen_settable_params(ossl_unused void *genctx,
    ossl_unused void *provctx)
{
    return NULL;
}

static void *sss_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    return NULL;
}

static void sss_gen_cleanup(void *genctx)
{
    return;
}

static void *sss_load(const void *reference, size_t reference_sz)
{
    return NULL;
}

static void sss_freedata(void *keydata)
{
    return;
}

static int sss_get_pkey_params(void *key, OSSL_PARAM params[])
{
    return 0;
}

static const OSSL_PARAM *sss_gettable_params(void *provctx)
{
    return NULL;
}

static int sss_set_pkey_params(void *key, const OSSL_PARAM params[])
{
    return 0;
}

static const OSSL_PARAM *sss_settable_params(void *provctx)
{
    return NULL;
}

static int sss_has(const void *keydata, int selection)
{
    return 0;
}

static int sss_match(const void *keydata1, const void *keydata2, int selection)
{
    return 0;
}

static int sss_validate(const void *keydata, int selection, int checktype)
{
    return 0;
}

static int sss_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    return 0;
}

static const OSSL_PARAM *sss_import_types(int selection)
{
    return NULL;
}

static int sss_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
    void *cbarg)
{
    return 0;
}

static const OSSL_PARAM *sss_export_types(int selection)
{
    return NULL;
}

static void *sss_dup(const void *keydata_from, int selection)
{
    return NULL;
}

static const OSSL_DISPATCH sss_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW_EX, (void (*)(void))sss_new_ex },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))sss_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))sss_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))sss_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))sss_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sss_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))sss_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sss_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sss_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))sss_get_pkey_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))sss_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))sss_set_pkey_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))sss_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sss_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))sss_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))sss_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sss_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))sss_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sss_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))sss_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))sss_dup },
    { 0, NULL }
};

static int sss_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME); 
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Provider for Shamirs Secret Sharing"))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM sss_keymgmt[] = {
    { "SSS", "provider=sss", sss_keymgmt_functions,
      "Shamirs Secret Sharing Algorithm" },
};

static const OSSL_ALGORITHM *sss_query(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;

    if (operation_id != OSSL_OP_KEYMGMT)
        return NULL;
    return sss_keymgmt;
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



