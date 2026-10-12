/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Intentionally incorrect: exports the right symbol but violates semantics.
 */
#include "../include/uoe_text_v1.h"
#include <string.h>

int uoe_text_normalize_v1(const char *input, char *output, size_t capacity) {
    if (!input || !output) return -1;
    size_t n = strlen(input);
    if (capacity <= n) return -2;
    memcpy(output, input, n + 1); /* Missing required prefix and uppercase. */
    return 0;
}
