/*==============================================================================
 example.c -- Example code for QCBOR

 Copyright (c) 2020, Laurence Lundblade. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 6/30/2020
=============================================================================*/


#include <stdio.h>
#include "example.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"

#define MAX_CYLINDERS 16

typedef struct
{
    UsefulBufC Manufacturer;
    uint64_t uNumCylinders;
    uint64_t uDisplacement;
    uint64_t uHorsePower;
    double uDesignedCompresion;
    struct {
        double uMeasuredCompression;
    } cylinders[MAX_CYLINDERS];
    bool bTurboCharged;
} Engine;


void EngineInit(Engine *pE)
{
    pE->uNumCylinders = 6;
    pE->bTurboCharged = false;
    pE->Manufacturer = UsefulBuf_FROM_SZ_LITERAL("Porsche");
    pE->uDisplacement = 3296;
    pE->uHorsePower = 210;
    pE->uDesignedCompresion = 9.1;
    pE->cylinders[0].uMeasuredCompression = 9.0;
    pE->cylinders[1].uMeasuredCompression = 9.2;
    pE->cylinders[2].uMeasuredCompression = 8.9;
    pE->cylinders[3].uMeasuredCompression = 8.9;
    pE->cylinders[4].uMeasuredCompression = 9.1;
    pE->cylinders[5].uMeasuredCompression = 9.0;
}


UsefulBufC EncodeEngine(const Engine *pEngine, UsefulBuf Buffer)
{
    QCBOREncodeContext EncodeCtx;

    QCBOREncode_Init(&EncodeCtx, Buffer);
    QCBOREncode_OpenMap(&EncodeCtx);
    QCBOREncode_AddTextToMap(&EncodeCtx, "Manufacturer", pEngine->Manufacturer);
    QCBOREncode_AddUInt64ToMap(&EncodeCtx, "NumCylinders", pEngine->uNumCylinders);
    QCBOREncode_AddUInt64ToMap(&EncodeCtx, "Displacement", pEngine->uDisplacement);
    QCBOREncode_AddUInt64ToMap(&EncodeCtx, "HorsePower", pEngine->uHorsePower);
    QCBOREncode_AddDoubleToMap(&EncodeCtx, "DesignedCompression", pEngine->uDesignedCompresion);
    QCBOREncode_OpenArrayInMap(&EncodeCtx, "Cylinders");
    for(uint64_t i = 0 ; i < pEngine->uNumCylinders; i++) {
        QCBOREncode_AddDouble(&EncodeCtx, pEngine->cylinders[i].uMeasuredCompression);
    }
    QCBOREncode_CloseArray(&EncodeCtx);
    QCBOREncode_AddBoolToMap(&EncodeCtx, "turbo", pEngine->bTurboCharged);
    QCBOREncode_CloseMap(&EncodeCtx);

    UsefulBufC EncodedCBOR;
    QCBORError uErr;
    uErr = QCBOREncode_Finish(&EncodeCtx, &EncodedCBOR);
    if(uErr != QCBOR_SUCCESS) {
        return NULLUsefulBufC;
    } else {
       return EncodedCBOR;
    }
}


UsefulBufC EncodeEngineIndefinteLen(const Engine *pEngine, UsefulBuf Buffer)
{
    QCBOREncodeContext EncodeCtx;

    QCBOREncode_Init(&EncodeCtx, Buffer);
    QCBOREncode_OpenMapIndefiniteLength(&EncodeCtx);
    QCBOREncode_AddTextToMap(&EncodeCtx, "Manufacturer", pEngine->Manufacturer);
    QCBOREncode_AddUInt64ToMap(&EncodeCtx, "Displacement", pEngine->uDisplacement);
    QCBOREncode_AddUInt64ToMap(&EncodeCtx, "HorsePower", pEngine->uHorsePower);
    QCBOREncode_AddDoubleToMap(&EncodeCtx, "DesignedCompression", pEngine->uDesignedCompresion);
    QCBOREncode_AddUInt64ToMap(&EncodeCtx, "NumCylinders", pEngine->uNumCylinders);
    QCBOREncode_OpenArrayIndefiniteLengthInMap(&EncodeCtx, "Cylinders");
    for(uint64_t i = 0 ; i < pEngine->uNumCylinders; i++) {
        QCBOREncode_AddDouble(&EncodeCtx, pEngine->cylinders[i].uMeasuredCompression);
    }
    QCBOREncode_CloseArrayIndefiniteLength(&EncodeCtx);
    QCBOREncode_AddBoolToMap(&EncodeCtx, "turbo", pEngine->bTurboCharged);
    QCBOREncode_CloseMapIndefiniteLength(&EncodeCtx);

    UsefulBufC EncodedCBOR;
    QCBORError uErr;
    uErr = QCBOREncode_Finish(&EncodeCtx, &EncodedCBOR);
    if(uErr != QCBOR_SUCCESS) {
        return NULLUsefulBufC;
    } else {
       return EncodedCBOR;
    }
}


/*
A -- require all fields ; easiest code
B -- all are optional; messiest code; should this be accommodate better?
C -- some are optional; not too hard

It is a protocol error to have the wrong type for a label.

 */

QCBORError DecodeEngine(UsefulBufC EncodedEngine, Engine *pE)
{
    QCBORDecodeContext DecodeCtx;

    QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&DecodeCtx);
    QCBORDecode_GetTextInMapSZ(&DecodeCtx, "Manufacturer", &(pE->Manufacturer));
    QCBORDecode_GetUInt64InMapSZ(&DecodeCtx, "Displacement", &(pE->uDisplacement));
    QCBORDecode_GetUInt64InMapSZ(&DecodeCtx, "HorsePower", &(pE->uHorsePower));
    QCBORDecode_GetDoubleInMapSZ(&DecodeCtx, "DesignedCompression", &(pE->uDesignedCompresion));
    QCBORDecode_GetBoolInMapSZ(&DecodeCtx, "turbo", &(pE->bTurboCharged));

    QCBORDecode_GetUInt64InMapSZ(&DecodeCtx, "NumCylinders", &(pE->uNumCylinders));

    /* Must check error before referencing pE->uNumCylinders to be sure it
     is valid. If any of the above errored, it won't be valid. */
    if(QCBORDecode_GetError(&DecodeCtx)) {
        return 100; // TODO: more error processing
    }

    if(pE->uNumCylinders > MAX_CYLINDERS) {
        return 900;
    }

    QCBORDecode_EnterArrayFromMapSZ(&DecodeCtx, "Cylinders");
    uint64_t i = 0;
    while(1) {
        QCBORDecode_GetDouble(&DecodeCtx, &(pE->cylinders[i].uMeasuredCompression));
        i++;
        if(i >= pE->uNumCylinders ) {
            break;
        }
    }
    QCBORDecode_ExitArray(&DecodeCtx);
    QCBORDecode_ExitMap(&DecodeCtx);

    QCBORError uErr = QCBORDecode_Finish(&DecodeCtx);

    return uErr;
}

#if 0
QCBORError CheckLabelAndType(const char *szLabel, uint8_t uQCBORType, QCBORItem *pItem)
{
    if(pItem->uLabelType != QCBOR_TYPE_TEXT_STRING) {
        return QCBOR_ERR_NOT_FOUND;
    }

    UsefulBufC Label = UsefulBuf_FromSZ(szLabel);

    if(UsefulBuf_Compare(Label, pItem->val.string)) {
        return QCBOR_ERR_NOT_FOUND;
    }

    if(pItem->uDataType != uQCBORType) {
        return QCBOR_ERR_UNEXPECTED_TYPE;
    }

    return QCBOR_SUCCESS;
}

void DecodeCylinders(QCBORDecodeContext *pDctx, Engine *pE, const QCBORItem *pItem)
{

}

QCBORError DecodeEngineBasic(UsefulBufC EncodedEngine, Engine *pE)
{
    QCBORDecodeContext DecodeCtx;

    QCBORDecode_Init(&DecodeCtx, EncodedEngine, 0);// TODO: fill in mode;

    QCBORItem Item;
    QCBORError uErr;

    uErr = QCBORDecode_GetNext(&DecodeCtx, &Item);
    if(uErr != QCBOR_SUCCESS) {
        goto Done;
    }
    if(Item.uDataType != QCBOR_TYPE_MAP) {
        uErr = 100;
        goto Done;
    }

    while(1) {
        uErr = QCBORDecode_GetNext(&DecodeCtx, &Item);
        if(uErr != QCBOR_SUCCESS) {
            goto Done;
        }
        if(Item.uDataType != QCBOR_TYPE_MAP) {
            uErr = 100;
            goto Done;
        }

        if(CheckLabelAndType("Manufacturer", QCBOR_TYPE_TEXT_STRING, &Item )) {
            if(Item.uDataType != QCBOR_TYPE_TEXT_STRING) {
                return 99; // TODO: what to do on wrong type?
            } else {
                // TODO: copy string or change data type
            }

        } else if(CheckLabel("NumCylinders", &Item)) {
          if(Item.uDataType != QCBOR_TYPE_INT64) {
              return 99; // TODO: what to do on wrong type?
          } else {
              // TODO: what about overflow
              pE->uNumCylinders = (uint8_t)Item.val.int64;
              // TODO: copy string or change data type
          }
        } else if(CheckLabel("Cylinders", &Item)) {
            DecodeCylinders(&DecodeCtx, pE, &Item);
         }

    }


Done:
    return uErr;
}

#endif





void RunQCborExample()
{
    Engine                  E, DecodedEngine;
    MakeUsefulBufOnStack(   EngineBuffer, 300);
    UsefulBufC              EncodedEngine;

    MakeUsefulBufOnStack(   InDefEngineBuffer, 300);
    UsefulBufC              InDefEncodedEngine;

    EngineInit(&E);

    EncodedEngine = EncodeEngine(&E, EngineBuffer);

    printf("Engine Encoded in %zu bytes\n", EncodedEngine.len);

    DecodeEngine(EncodedEngine, &DecodedEngine);


    InDefEncodedEngine = EncodeEngineIndefinteLen(&E, InDefEngineBuffer);

    printf("Indef Engine Encoded in %zu bytes\n", InDefEncodedEngine.len);

}
