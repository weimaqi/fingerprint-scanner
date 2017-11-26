#include <stdio.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

main()
{
  static struct pam_conv pc = { misc_conv, NULL };
  pam_handle_t *ph = NULL;
  char *env[] = { "HOME=/root" };
  int r, ret;

  if ((r = pam_start("fingerprint-biometric", "fsbano", &pc, &ph)) != PAM_SUCCESS) {
      fprintf(stderr, "Failure starting pam: %s\n", pam_strerror(ph, r));
      return 1;
  }

  if ((r = pam_authenticate(ph, 0)) != PAM_SUCCESS) {
        fprintf(stderr, "Failed to authenticate: %s\n", pam_strerror(ph, r));
        ret = 1;
  } else {
        printf("Authentication successful.\n");
        setuid(0);
        setgid(0);
        execve("/bin/bash", NULL, env);
        ret = 0;
  }

  if ((r = pam_end(ph, r)) != PAM_SUCCESS)
     fprintf(stderr, "Failure shutting down pam: %s\n", pam_strerror(ph, r));

}
