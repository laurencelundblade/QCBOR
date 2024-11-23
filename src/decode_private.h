/*==============================================================================
 Copyright (c) 2016-2018, The Linux Foundation.
 Copyright (c) 2018-2024, Laurence Lundblade.
 Copyright (c) 2021, Arm Limited.
 All rights reserved.

 Created on 11/14/24 from qcbor_decode.c


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors, nor the name "Laurence Lundblade" may be used to
      endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 =============================================================================*/

#ifndef decode_private_h
#define decode_private_h


QCBORError
QCBORDecode_Private_GetNextTagContent(QCBORDecodeContext *pMe,
                                      QCBORItem          *pDecodedItem);

void
QCBORDecode_Private_ProcessTagItemMulti(QCBORDecodeContext      *pMe,
                                        QCBORItem               *pItem,
                                        const uint8_t            uTagRequirement,
                                        const uint8_t            uQCBORTypes[],
                                        const uint64_t           uTagNumbers[],
                                        QCBORTagContentCallBack *pfCB,
                                        size_t                   uOffset);


void
QCBORDecode_Private_ProcessTagItem(QCBORDecodeContext      *pMe,
                                   QCBORItem               *pItem,
                                   const uint8_t            uTagRequirement,
                                   const uint8_t            uQCBORTypes[],
                                   const uint64_t           uTagNumber,
                                   QCBORTagContentCallBack *pfCB,
                                   size_t                   uOffset);

void
QCBORDecode_Private_GetItemInMapNoCheckSZ(QCBORDecodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uQcborType,
                                  QCBORItem          *pItem,
                                  size_t             *puOffset);

void
QCBORDecode_Private_GetItemInMapNoCheckN(QCBORDecodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uQcborType,
                                 QCBORItem          *pItem,
                                 size_t             *puOffset);

static inline void
QCBORDecode_Private_GetAndTell(QCBORDecodeContext *pMe, QCBORItem *Item, size_t *uOffset)
{
#ifndef QCBOR_DISABLE_TAGS
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   *uOffset = QCBORDecode_Tell(pMe);
#else
   *uOffset = SIZE_MAX;

#endif /* ! QCBOR_DISABLE_TAGS */
   pMe->uLastError = (uint8_t)QCBORDecode_Private_GetNextTagContent(pMe, Item);
}


#endif /* decode_private_h */
