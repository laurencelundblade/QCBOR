/*==============================================================================
 err_to_str.c -- strings names for errors

 Copyright (c) 2020, Patrick Uiterwijk. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 3/21/20
 =============================================================================*/

#include "qcbor/qcbor_common.h"

#define _ERR_TO_STR(errpart) case QCBOR_##errpart: return "QCBOR_" #errpart;

const char *qcbor_err_to_str(QCBORError err) {
	switch (err) {
	_ERR_TO_STR(SUCCESS)
	_ERR_TO_STR(ERR_BUFFER_TOO_SMALL)
	_ERR_TO_STR(ERR_ARRAY_NESTING_TOO_DEEP)
	_ERR_TO_STR(ERR_ARRAY_TOO_LONG)
	_ERR_TO_STR(ERR_TOO_MANY_CLOSES)
	_ERR_TO_STR(ERR_UNSUPPORTED)
	_ERR_TO_STR(ERR_HIT_END)
	_ERR_TO_STR(ERR_BUFFER_TOO_LARGE)
	_ERR_TO_STR(ERR_INT_OVERFLOW)
	_ERR_TO_STR(ERR_MAP_LABEL_TYPE)
	_ERR_TO_STR(ERR_ARRAY_OR_MAP_STILL_OPEN)
	_ERR_TO_STR(ERR_DATE_OVERFLOW)
	_ERR_TO_STR(ERR_BAD_TYPE_7)
	_ERR_TO_STR(ERR_BAD_OPT_TAG)
	_ERR_TO_STR(ERR_EXTRA_BYTES)
	_ERR_TO_STR(ERR_CLOSE_MISMATCH)
	_ERR_TO_STR(ERR_NO_STRING_ALLOCATOR)
	_ERR_TO_STR(ERR_INDEFINITE_STRING_CHUNK)
	_ERR_TO_STR(ERR_STRING_ALLOCATE)
	_ERR_TO_STR(ERR_BAD_BREAK)
	_ERR_TO_STR(ERR_TOO_MANY_TAGS)
	_ERR_TO_STR(ERR_BAD_INT)
	_ERR_TO_STR(ERR_NO_MORE_ITEMS)
	_ERR_TO_STR(ERR_BAD_EXP_AND_MANTISSA)
	_ERR_TO_STR(ERR_STRING_TOO_LONG)

	default:
		return "Invalid error";
	}
}
