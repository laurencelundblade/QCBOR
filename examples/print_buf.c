/*
 * print_buf.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "print_buf.h"
#include <stdio.h>


void
print_useful_buf(const char *string_label, struct q_useful_buf_c buf)
{
    if(string_label) {
        printf("%s", string_label);
    }

    printf("    %ld bytes\n", buf.len);

    printf("    ");

    size_t i;
    for(i = 0; i < buf.len; i++) {
        const uint8_t Z = ((const uint8_t *)buf.ptr)[i];
        printf("%02x ", Z);
        if((i % 16) == 15) {
            printf("\n    ");
        }
    }
    printf("\n");

    fflush(stdout);
}
