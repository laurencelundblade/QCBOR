/*
 * print_buf.c
 *
 * Copyright 2023, Laurence Lundblade
 *
 *  Created by Laurence Lundblade on 2/21/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef print_buf_h
#define print_buf_h

#include "t_cose/q_useful_buf.h"


/**
 * \brief  Print a q_useful_buf_c on stdout in hex ASCII text.
 *
 * \param[in] string_label   A string label to output first
 * \param[in] buf            The q_useful_buf_c to output.
 *
 * This is just for pretty printing.
 */
void
print_useful_buf(const char           *string_label,
                 struct q_useful_buf_c buf);


#endif /* print_buf_h */
