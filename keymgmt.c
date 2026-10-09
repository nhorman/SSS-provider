#include <openssl/core.h> 
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/bn.h>
#include <openssl/err.h>

static int sss_gen_set_params(void *genctx, const OSSL_PARAM params[]);
static int sss_set_pkey_params(void *key, const OSSL_PARAM params[]);

typedef struct sss_common_st {
    size_t poly_order;
} SSS_COMMON;

typedef struct sss_privkey_st {
    BIGNUM **coeffs;
} SSS_PRIVKEY;

typedef struct sss_point_st {
    BIGNUM *x;
    BIGNUM *y;
} SSS_POINT;

typedef struct sss_pubkey_st {
    size_t num_points;
    SSS_POINT *points;
} SSS_PUBKEY;

typedef struct sss_key_st {
    SSS_COMMON common;
    SSS_PRIVKEY *priv;
    SSS_PUBKEY *pub;
} SSS_KEY;

typedef struct sss_gen_ctx_st {
    size_t cbits;
    size_t poly_order;
    int selection;
} SSS_GEN_CTX;

#define SSS_HAS_PRIVKEY(x) ((x)->priv != NULL)
#define SSS_SET_PRIVKEY(x) ((x)->priv = (x) + 1)
#define SSS_CLEAR_PRIVKEY(x) ((x)->priv = NULL)
#define SSS_HAS_PUBKEY(x) ((x)->pub != NULL)
#define SSS_SET_PUBKEY(x) ((x)->priv = ((SSS_PRIVKEY *)((x) + 1)) + 1)
#define SSS_CLEAR_PUBKEY(x) ((x)->pub = NULL)

static void *sss_new_ex(void *provctx, const OSSL_PARAM params[])
{
    SSS_KEY *newkey = OPENSSL_zalloc(sizeof(SSS_KEY) + sizeof(SSS_PRIVKEY));

    if (newkey == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    sss_set_pkey_params(newkey, params);
    return newkey;
}

static void *sss_gen_init(void *provctx, int selection,
    const OSSL_PARAM params[])
{
    SSS_GEN_CTX *newctx = OPENSSL_zalloc(sizeof(SSS_GEN_CTX));

    if (newctx == NULL)
        return NULL;

    newctx->selection = selection;
    newctx->cbits = 64;
    newctx->poly_order = 4;
    return newctx;
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

static void sss_free_privkey(SSS_KEY *key)
{
    SSS_PRIVKEY *privkey = key->priv;
    int i;

    for (i = 0; i < key->common.poly_order; i++)
        BN_clear_free(privkey->coeffs[i]);

    OPENSSL_free(privkey->coeffs);
    SSS_CLEAR_PRIVKEY(key);
}

static void sss_free_pubkey(SSS_KEY *key)
{
    SSS_PUBKEY *pubkey = key->pub;
    int i;

    for (i = 0; i < pubkey->num_points; i++) {
        BN_free(pubkey->points[i].x);
        BN_free(pubkey->points[i].y);
    }
    OPENSSL_free(pubkey->points);
    SSS_CLEAR_PUBKEY(key);
}

static void sss_freedata(void *keydata)
{
    SSS_KEY *key = (SSS_KEY *)keydata;

    if (key == NULL)
        return;
    if (SSS_HAS_PRIVKEY(key))
        sss_free_privkey(key);
    if (SSS_HAS_PUBKEY(key))
        sss_free_pubkey(key);
    OPENSSL_free(key);
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

static const OSSL_PARAM *sss_settable_pkey_params(void *provctx)
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
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))sss_settable_pkey_params },
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

static const OSSL_ALGORITHM sss_keymgmt[] = {
    { "SSS", "provider=sss", sss_keymgmt_functions,
      "Shamirs Secret Sharing Algorithm" },
    {NULL, NULL, NULL }
};

const OSSL_ALGORITHM *get_sss_keymgmt()
{
    return sss_keymgmt;
}


