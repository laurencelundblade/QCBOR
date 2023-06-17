/*
 * t_cose_qcbor_gap.h
 *
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 5/29/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_qcbor_gap_h
#define t_cose_qcbor_gap_h

#include "qcbor/qcbor_decode.h"

#if !defined(QCBOR_MAJOR_VERSION) || QCBOR_MAJOR_VERSION < 2



/* These two functions are planned for QCBOR 2, but we want t_cose
 * to run with QCBOR 1. This is possible because with a layering
 * violation where the implementation of these two functions assumes
 * particularly internal QCBOR state. While that state is private,
 * it has been stable for years and all major released versions of
 * QCBOR 1.
 */


/**
 * Holds saved decoder state for QCBORDecode_SaveCursor() and QCBORDecode_RestoreCursor()
 */
typedef struct {
    /* Private data structure */
    uint8_t            last_error;
    uint32_t           offset;
    QCBORDecodeNesting Nesting;
    // TODO: Should more be saved and restored?
} QCBORSaveDecodeCursor;


/*
 *
 * This saves the decode state such that any decoding done after
 * this call can be abandoned with a call to QCBORDecode_RestoreCursor().
 */
void QCBORDecode_SaveCursor(QCBORDecodeContext *pCtx, QCBORSaveDecodeCursor *cursor);

void QCBORDecode_RestoreCursor(QCBORDecodeContext *pCtx, const QCBORSaveDecodeCursor *cursor);

#endif /* QCBOR_MAJOR_VERSION >= 2 */

#endif /* t_cose_qcbor_gap_h */
