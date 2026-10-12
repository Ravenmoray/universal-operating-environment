/* SPDX-License-Identifier: AGPL-3.0-or-later
 * UOE project-owned experimental C ABI, version 1.
 * No compatibility claim about third-party software.
 */
#ifndef UOE_TEXT_V1_H
#define UOE_TEXT_V1_H
#include <stddef.h>

/*
 * Exported symbol: uoe_text_normalize_v1
 *
 * Transform ASCII a-z to A-Z, preserve all other bytes, prepend "UOE/1:".
 * Input is a NUL-terminated byte sequence, maximum 512 bytes (excluding NUL).
 * Outputs are NUL-terminated on success.
 *  0 = success
 * -1 = NULL input or output
 * -2 = output capacity insufficient, output MUST remain untouched
 * -3 = input too long, output MUST remain untouched
 */
typedef int (*uoe_text_normalize_v1_fn)(const char *input, char *output,
                                         size_t output_capacity);
#define UOE_TEXT_V1_SYMBOL "uoe_text_normalize_v1"
#define UOE_TEXT_V1_PREFIX "UOE/1:"
#define UOE_TEXT_V1_MAX_INPUT 512
#endif
