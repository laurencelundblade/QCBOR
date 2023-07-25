/*
 * t_cose_qcbor_gap.c
 *
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 5/29/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#include "t_cose_qcbor_gap.h"


#if !defined(QCBOR_MAJOR_VERSION) || QCBOR_MAJOR_VERSION < 2

#include "qcbor/qcbor_decode.h"


/*
 * Public Function. See t_cose_qcbor_gap.h
 */
void QCBORDecode_SaveCursor(QCBORDecodeContext *pMe,
                            QCBORSaveDecodeCursor *cursor)
{
    cursor->Nesting = pMe->nesting;
    cursor->offset  = (uint32_t)UsefulInputBuf_Tell(&(pMe->InBuf));
    cursor->last_error = pMe->uLastError;
}


/*
 * Public Function. See t_cose_qcbor_gap.h
 */
void QCBORDecode_RestoreCursor(QCBORDecodeContext *pMe,
                               const QCBORSaveDecodeCursor *cursor)
{
    pMe->nesting = cursor->Nesting;
    UsefulInputBuf_Seek(&(pMe->InBuf), cursor->offset);
    pMe->uLastError = cursor->last_error;
}

#endif
