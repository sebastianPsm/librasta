#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <string.h>
#include <stdbool.h>

#define HEAP_HINT NULL
#define LARGE_TEMP_SZ 4096

#define CERT_C "DE"
#define CERT_ST "Brandenburg"
#define CERT_L "Potsdam"
#define CERT_ORG "RaSTA"
#define CERT_OU "Testing"
#define CERT_CN_CA "Test CA"
#define CERT_CN_SERVER "localhost"
#define CERT_EMAIL "root@localhost"

static void create_certificate(bool is_ca, const char *cert_path, const char *key_path, ecc_key *caKey, byte *ca_cert_buf, int *ca_cert_buf_len){
    int ret = 0;

    Cert newCert;

    FILE* file;

    int derBufSz;
    byte *derBuf = NULL;
    byte* pemBuf   = NULL;

    /* for MakeCert and SignCert */
    WC_RNG rng;
    ecc_key newKey;
    int initRng = 0, initNewKey = 0;

    int pemBufSz;

    derBuf = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) goto exit;
    XMEMSET(derBuf, 0, LARGE_TEMP_SZ);

    pemBuf = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (pemBuf == NULL) goto exit;
    XMEMSET(pemBuf, 0, LARGE_TEMP_SZ);

    /*------------------------------------------------------------------------*/
    /* Generate new private key to go with our new cert */
    /*------------------------------------------------------------------------*/
    ret = wc_InitRng(&rng);
    if (ret != 0) goto exit;
    initRng = 1;
    ret = wc_ecc_init(is_ca?caKey : &newKey);
    if (ret != 0) goto exit;
    initNewKey = 1;

    ret = wc_ecc_make_key(&rng, 32, is_ca?caKey : &newKey);
    if (ret != 0) goto exit;

    /*------------------------------------------------------------------------*/
    /* Create a new certificate using SUBJECT information from ca cert
     * for ISSUER information in generated cert */
    /*------------------------------------------------------------------------*/

    wc_InitCert(&newCert);

    strncpy(newCert.subject.country, CERT_C, CTC_NAME_SIZE);
    strncpy(newCert.subject.state, CERT_ST, CTC_NAME_SIZE);
    strncpy(newCert.subject.locality, CERT_L, CTC_NAME_SIZE);
    strncpy(newCert.subject.org, CERT_ORG, CTC_NAME_SIZE);
    strncpy(newCert.subject.unit, CERT_OU, CTC_NAME_SIZE);
    strncpy(newCert.subject.commonName, is_ca?CERT_CN_CA : CERT_CN_SERVER, CTC_NAME_SIZE);
    strncpy(newCert.subject.email, CERT_EMAIL, CTC_NAME_SIZE);


    newCert.isCA    = is_ca ? 1 : 0;
    newCert.sigType = CTC_SHA256wECDSA;

    if(is_ca) {
        strncpy(newCert.issuer.country, CERT_C, CTC_NAME_SIZE);
        strncpy(newCert.issuer.state, CERT_ST, CTC_NAME_SIZE);
        strncpy(newCert.issuer.locality, CERT_L, CTC_NAME_SIZE);
        strncpy(newCert.issuer.org, CERT_ORG, CTC_NAME_SIZE);
        strncpy(newCert.issuer.unit, CERT_OU, CTC_NAME_SIZE);
        // CA signs itself
        strncpy(newCert.issuer.commonName, CERT_CN_CA, CTC_NAME_SIZE);
        strncpy(newCert.issuer.email, CERT_EMAIL, CTC_NAME_SIZE);
    }
    else{
        ret = wc_SetIssuerBuffer(&newCert,ca_cert_buf,*ca_cert_buf_len);
        if(ret < 0){
            fprintf(stderr, "Error setting issuer: %s",wc_GetErrorString(ret));
            goto exit;
        }
    }

    ret = wc_MakeCert(&newCert, derBuf, LARGE_TEMP_SZ, NULL, is_ca?caKey : &newKey, &rng);

    if (ret < 0){
        fprintf(stderr, "Error creating certificate: %s",wc_GetErrorString(ret));
        goto exit;
    }

    ret = wc_SignCert(newCert.bodySz, newCert.sigType, derBuf, LARGE_TEMP_SZ,
                      NULL, caKey, &rng);
    if (ret < 0) goto exit;

    derBufSz = ret;

    if(is_ca){
        memcpy(ca_cert_buf,derBuf,derBufSz);
        *ca_cert_buf_len = derBufSz;
    }

    /*------------------------------------------------------------------------*/
    /* convert the der to a pem and write it to a file */
    /*------------------------------------------------------------------------*/

    pemBufSz = wc_DerToPem(derBuf, derBufSz, pemBuf, LARGE_TEMP_SZ, CERT_TYPE);
    if (pemBufSz < 0) goto exit;

    file = fopen(cert_path, "wb");
    if (!file) {
        fprintf(stderr,"failed to open file: %s\n", cert_path);
        perror("opening file: ");
        goto exit;
    }
    fwrite(pemBuf, 1, pemBufSz, file);
    fclose(file);

    if(key_path) {

        derBufSz = wc_EccPrivateKeyToDer(&newKey,derBuf,LARGE_TEMP_SZ);

        if(derBufSz < 0) goto exit;

        pemBufSz = wc_DerToPem(derBuf, derBufSz, pemBuf, LARGE_TEMP_SZ, ECC_PRIVATEKEY_TYPE);

        if (pemBufSz < 0) goto exit;

        file = fopen(key_path, "w");
        if (!file) {
            fprintf(stderr,"failed to open file: %s\n", cert_path);
            perror("opening file: ");
            goto exit;
        }
        fwrite(pemBuf, 1, pemBufSz, file);
        fclose(file);
    }



    ret = 0; /* success */

    exit:

    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (initNewKey)
        wc_ecc_free(&newKey);
    if (initRng) {
        wc_FreeRng(&rng);
    }

    if(ret){
        exit(ret);
    }
}

void create_certificates(const char *ca_cert_path, const char *server_cert_path, const char *server_key_path){
    ecc_key ca_key;
    byte *ca_cert_buf = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    int ca_cert_len = LARGE_TEMP_SZ;
    create_certificate(true,ca_cert_path,NULL,&ca_key,ca_cert_buf,&ca_cert_len);

    create_certificate(false,server_cert_path,server_key_path,&ca_key,ca_cert_buf,&ca_cert_len);

    wc_ecc_free(&ca_key);
    XFREE(ca_cert_buf,HEAP_HINT,DYNAMIC_TYPE_TMP_BUFFER);
    printf("Generated new certificates - make sure to restart any client!");
}
