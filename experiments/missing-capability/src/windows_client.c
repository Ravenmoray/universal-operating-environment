/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Windows PE variant of the UOE project-owned missing-capability fixture.
 * Cross-compiled and format-checked on Linux; execution is a separate goal.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../include/uoe_text_v1.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char result[1024];
    if (argc != 3) {
        fprintf(stderr, "usage: windows_client <dll-path> <text>\n");
        return 64;
    }
    HMODULE handle = LoadLibraryA(argv[1]);
    if (handle == NULL) {
        fprintf(stderr, "UOE_ERR_LIBRARY: Windows error=%lu\n",
                (unsigned long)GetLastError());
        return 40;
    }
    FARPROC symbol = GetProcAddress(handle, UOE_TEXT_V1_SYMBOL);
    if (symbol == NULL) {
        fprintf(stderr, "UOE_ERR_SYMBOL: Windows error=%lu\n",
                (unsigned long)GetLastError());
        (void)FreeLibrary(handle);
        return 41;
    }
    /* x86-64 Win32 function pointer representations are the same size. */
    uoe_text_normalize_v1_fn normalize;
    _Static_assert(sizeof(normalize) == sizeof(symbol), "pointer ABI mismatch");
    memcpy(&normalize, &symbol, sizeof normalize);
    int status = normalize(argv[2], result, sizeof result);
    (void)FreeLibrary(handle);
    if (status != 0) {
        fprintf(stderr, "UOE_ERR_CONTRACT: status=%d\n", status);
        return 42;
    }
    puts(result);
    return 0;
}
