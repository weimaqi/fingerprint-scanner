#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <dlfcn.h>

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_IGNORE; }
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)   { return PAM_IGNORE; }
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_IGNORE; }
PAM_EXTERN int pam_sm_authenticate (pam_handle_t *pamh, int flags,int argc, const char **argv) {
    printf("Biometric Fingerprint Verification:\n");
    void* sdk = dlopen("/usr/lib64/libcis_sdk.so", RTLD_NOW);
    int (*CIS_SDK_Versao)(void);
    int (*CIS_SDK_Biometrico_Iniciar)(int);
    int (*CIS_SDK_Biometrico_LerDigital)(char *);
    int (*CIS_SDK_Biometrico_CompararDigital)(char *, char*);
    void (*CIS_SDK_Biometrico_Finalizar)(void);
    FILE *tpl = fopen("/tmp/fingerprint.tpl", "rb");
    unsigned char fingerprint[668];
    unsigned char template[668];

    if (!sdk) {
      fprintf(stderr, "%s\n", dlerror());
      exit(EXIT_FAILURE);     
    }
    *(int **) (&CIS_SDK_Versao) = dlsym(sdk, "CIS_SDK_Versao");
    *(int **) (&CIS_SDK_Biometrico_Iniciar) = dlsym(sdk, "CIS_SDK_Biometrico_Iniciar");
    *(int **) (&CIS_SDK_Biometrico_LerDigital) = dlsym(sdk, "CIS_SDK_Biometrico_LerDigital");
    *(int **) (&CIS_SDK_Biometrico_CompararDigital) = dlsym(sdk, "CIS_SDK_Biometrico_CompararDigital");
    *(void **) (&CIS_SDK_Biometrico_Finalizar) = dlsym(sdk, "CIS_SDK_Biometrico_Finalizar");

    CIS_SDK_Biometrico_Iniciar(0);
    CIS_SDK_Biometrico_LerDigital(fingerprint);
    fread(template,sizeof(template),668,tpl);
    int r = CIS_SDK_Biometrico_CompararDigital(template, fingerprint);
    if (r == 1) {
       return PAM_SUCCESS;
    }
    return PAM_AUTH_ERR;
    CIS_SDK_Biometrico_Finalizar();
    dlclose(sdk);
}

