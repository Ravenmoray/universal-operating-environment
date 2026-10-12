/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Reference implementation used as a controlled candidate, not AI output.
 */
#include "../include/uoe_text_v1.h"
#include <string.h>

UOE_EXPORT int uoe_text_normalize_v1(const char *input, char *output, size_t capacity) {
    if (input == NULL || output == NULL) return -1;
    size_t length = strlen(input);
    if (length > UOE_TEXT_V1_MAX_INPUT) return -3;
    const size_t prefix = sizeof(UOE_TEXT_V1_PREFIX) - 1;
    if (capacity <= prefix + length) return -2;
    memcpy(output, UOE_TEXT_V1_PREFIX, prefix);
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)input[i];
        output[prefix + i] = (char)((c >= 'a' && c <= 'z') ? c - ('a' - 'A') : c);
    }
    output[prefix + length] = '\0';
    return 0;
}
