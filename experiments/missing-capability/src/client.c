/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Harmless, project-owned ELF fixture. Do not use to load untrusted libraries.
 */
#include "../include/uoe_text_v1.h"
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
    char result[1024];
    if (argc != 3) {
        fprintf(stderr, "usage: client <library-path> <text>\n");
        return 64;
    }

    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "UOE_ERR_LIBRARY: %s\n", dlerror());
        return 40;
    }

    (void)dlerror(); /* Clear previous dynamic-loader errors. */
    void *symbol = dlsym(handle, UOE_TEXT_V1_SYMBOL);
    const char *error = dlerror();
    if (error != NULL || symbol == NULL) {
        fprintf(stderr, "UOE_ERR_SYMBOL: %s\n", error ? error : "missing symbol");
        (void)dlclose(handle);
        return 41;
    }

    /*
     * POSIX dlsym returns a function symbol through void*. This pattern is
     * standard on the Linux/POSIX systems targeted by this fixture.
     */
    uoe_text_normalize_v1_fn normalize;
    *(void **)(&normalize) = symbol;
    int status = normalize(argv[2], result, sizeof result);
    (void)dlclose(handle);
    if (status != 0) {
        fprintf(stderr, "UOE_ERR_CONTRACT: status=%d\n", status);
        return 42;
    }
    puts(result);
    return 0;
}
