/* SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * AI-authored candidate, 2026-10-12, using the public UOE v1 interface
 * contract. Authored by ChatGPT (GPT-6) during project collaboration.
 *
 * DISCLOSURE: This is NOT a blinded experiment. The reference implementation
 * and public verification harness existed and were available in the project.
 * Passing tests show behavioral equivalence for tested cases, not autonomous
 * discovery or independently validated compatibility with external software.
 */
#include "include/uoe_text_v1.h"
#include <stddef.h>
#include <string.h>

UOE_EXPORT int uoe_text_normalize_v1(const char *input,
                                      char *output,
                                      size_t output_capacity)
{
    if (input == NULL || output == NULL) {
        return -1;
    }

    /* Do not read indefinitely in search of NUL if an input is too long. */
    size_t length = 0;
    while (length <= UOE_TEXT_V1_MAX_INPUT && input[length] != '\0') {
        ++length;
    }
    if (length > UOE_TEXT_V1_MAX_INPUT) {
        return -3;
    }

    const char prefix[] = UOE_TEXT_V1_PREFIX;
    const size_t prefix_length = sizeof(prefix) - 1;

    /* Verify capacity before modifying output, including the terminating NUL. */
    if (output_capacity <= prefix_length + length) {
        return -2;
    }

    /* For the stated non-overlapping input/output contract. */
    memcpy(output, prefix, prefix_length);
    for (size_t offset = 0; offset < length; ++offset) {
        const unsigned char byte = (unsigned char)input[offset];
        if (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') {
            output[prefix_length + offset] = (char)(byte - ('a' - 'A'));
        } else {
            output[prefix_length + offset] = (char)byte;
        }
    }
    output[prefix_length + length] = '\0';
    return 0;
}
