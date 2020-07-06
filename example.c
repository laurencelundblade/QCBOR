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
    int64_t uNumCylinders;
    int64_t uDisplacement;
    int64_t uHorsePower;
    double dDesignedCompresion;
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
    pE->dDesignedCompresion = 9.1;
    pE->cylinders[0].uMeasuredCompression = 9.0;
    pE->cylinders[1].uMeasuredCompression = 9.2;
    pE->cylinders[2].uMeasuredCompression = 8.9;
    pE->cylinders[3].uMeasuredCompression = 8.9;
    pE->cylinders[4].uMeasuredCompression = 9.1;
    pE->cylinders[5].uMeasuredCompression = 9.0;
}


bool EngineCompare(Engine *pE1, Engine *pE2)
{
    if(pE1->uNumCylinders != pE2->uNumCylinders) {
        return false;
    }
    if(pE1->bTurboCharged != pE2->bTurboCharged) {
        return false;
    }
    if(pE1->uDisplacement != pE2->uDisplacement) {
        return false;
    }
    if(pE1->uHorsePower != pE2->uHorsePower) {
        return false;
    }
    if(pE1->dDesignedCompresion != pE2->dDesignedCompresion) {
        return false;
    }
    for(int64_t i = 0; i < pE2->uNumCylinders; i++) {
        if(pE1->cylinders[i].uMeasuredCompression !=
           pE2->cylinders[i].uMeasuredCompression) {
            return false;
        }
    }

    if(UsefulBuf_Compare(pE1->Manufacturer, pE2->Manufacturer)) {
        return false;
    }

    return true;
}


UsefulBufC EncodeEngine(const Engine *pEngine, UsefulBuf Buffer)
{
    /* Initialize th encoder with the buffer big enough to hold the expected output.
     If it is too small, QCBOREncode_Finish() will return an error. */
    QCBOREncodeContext EncodeCtx;
    QCBOREncode_Init(&EncodeCtx, Buffer);

    /* Proceed output all the items, letting the internal error
     tracking do its work. */
    QCBOREncode_OpenMap(&EncodeCtx);
    QCBOREncode_AddTextToMap(&EncodeCtx, "Manufacturer", pEngine->Manufacturer);
    QCBOREncode_AddInt64ToMap(&EncodeCtx, "NumCylinders", pEngine->uNumCylinders);
    QCBOREncode_AddInt64ToMap(&EncodeCtx, "Displacement", pEngine->uDisplacement);
    QCBOREncode_AddInt64ToMap(&EncodeCtx, "Horsepower", pEngine->uHorsePower);
    QCBOREncode_AddDoubleToMap(&EncodeCtx, "DesignedCompression", pEngine->dDesignedCompresion);
    QCBOREncode_OpenArrayInMap(&EncodeCtx, "Cylinders");
    for(int64_t i = 0 ; i < pEngine->uNumCylinders; i++) {
        QCBOREncode_AddDouble(&EncodeCtx, pEngine->cylinders[i].uMeasuredCompression);
    }
    QCBOREncode_CloseArray(&EncodeCtx);
    QCBOREncode_AddBoolToMap(&EncodeCtx, "turbo", pEngine->bTurboCharged);
    QCBOREncode_CloseMap(&EncodeCtx);

    /* Get the pointer and length of the encoded output. If there was
     anny error it will be returned here. */
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
    QCBOREncode_AddInt64ToMap(&EncodeCtx, "Displacement", pEngine->uDisplacement);
    QCBOREncode_AddInt64ToMap(&EncodeCtx, "Horsepower", pEngine->uHorsePower);
    QCBOREncode_AddDoubleToMap(&EncodeCtx, "DesignedCompression", pEngine->dDesignedCompresion);
    QCBOREncode_AddInt64ToMap(&EncodeCtx, "NumCylinders", pEngine->uNumCylinders);
    QCBOREncode_OpenArrayIndefiniteLengthInMap(&EncodeCtx, "Cylinders");
    for(int64_t i = 0 ; i < pEngine->uNumCylinders; i++) {
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



typedef enum  {
    EngineSuccess,
    CBORNotWellFormed,
    TooManyCylinders,
    EngineProtocolerror,
    WrongNumberOfCylinders
} EngineDecodeErrors;


EngineDecodeErrors ConvertError(QCBORError uErr)
{
    EngineDecodeErrors uReturn;

    switch(uErr)
    {
        case QCBOR_SUCCESS:
            uReturn = EngineSuccess;
            break;

        case QCBOR_ERR_HIT_END:
            uReturn = CBORNotWellFormed;
            break;

        default:
            uReturn = EngineProtocolerror;
            break;
    }

    return uReturn;
}


/*
 Decode using the advanced decode features. This pulls in more
 code from the QCBOR library, but is much simpler and
 roughly mirrors the encoding implementation.
 */
EngineDecodeErrors DecodeEngine(UsefulBufC EncodedEngine, Engine *pE)
{
    QCBORError uErr;
    QCBORDecodeContext DecodeCtx;

    QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&DecodeCtx);
    QCBORDecode_GetTextInMapSZ(&DecodeCtx, "Manufacturer", &(pE->Manufacturer));
    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Displacement", &(pE->uDisplacement));
    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Horsepower", &(pE->uHorsePower));
    QCBORDecode_GetDoubleInMapSZ(&DecodeCtx, "DesignedCompression", &(pE->dDesignedCompresion));
    QCBORDecode_GetBoolInMapSZ(&DecodeCtx, "turbo", &(pE->bTurboCharged));

    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "NumCylinders", &(pE->uNumCylinders));

    /* Must check error before referencing pE->uNumCylinders to be sure it
     is valid. If any of the above errored, it won't be valid. */
    uErr = QCBORDecode_GetError(&DecodeCtx);
    if(uErr != QCBOR_SUCCESS) {
        goto Done;
    }

    if(pE->uNumCylinders > MAX_CYLINDERS) {
        return TooManyCylinders;
    }

    QCBORDecode_EnterArrayFromMapSZ(&DecodeCtx, "Cylinders");
    for(int64_t i = 0; i < pE->uNumCylinders; i++) {
        QCBORDecode_GetDouble(&DecodeCtx, &(pE->cylinders[i].uMeasuredCompression));
    }
    QCBORDecode_ExitArray(&DecodeCtx);
    QCBORDecode_ExitMap(&DecodeCtx);

    /* Catch the remainder of errors here */
    uErr = QCBORDecode_Finish(&DecodeCtx);

Done:
    return ConvertError(uErr);
}



EngineDecodeErrors DecodeEngineXX(UsefulBufC EncodedEngine, Engine *pE)
{
    QCBORError uErr;
    QCBORDecodeContext DecodeCtx;

    QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&DecodeCtx);

    QCBORItem XX[7];
    XX[0].uLabelType = QCBOR_TYPE_TEXT_STRING;
    XX[0].label.string = UsefulBuf_FROM_SZ_LITERAL("Manufacturer");
    XX[0].uDataType = QCBOR_TYPE_TEXT_STRING;

    XX[1].uLabelType = QCBOR_TYPE_TEXT_STRING;
    XX[1].label.string = UsefulBuf_FROM_SZ_LITERAL("Displacement");
    XX[1].uDataType = QCBOR_TYPE_INT64;

    XX[2].uLabelType = QCBOR_TYPE_TEXT_STRING;
    XX[2].label.string = UsefulBuf_FROM_SZ_LITERAL("Horsepower");
    XX[2].uDataType = QCBOR_TYPE_INT64;

    XX[3].uLabelType = QCBOR_TYPE_TEXT_STRING;
    XX[3].label.string = UsefulBuf_FROM_SZ_LITERAL("DesignedCompression");
    XX[3].uDataType = QCBOR_TYPE_DOUBLE;

    XX[4].uLabelType = QCBOR_TYPE_TEXT_STRING;
    XX[4].label.string = UsefulBuf_FROM_SZ_LITERAL("turbo");
    XX[4].uDataType = QCBOR_TYPE_ANY;

    XX[5].uLabelType = QCBOR_TYPE_TEXT_STRING;
    XX[5].label.string = UsefulBuf_FROM_SZ_LITERAL("NumCylinders");
    XX[5].uDataType = QCBOR_TYPE_INT64;

    XX[6].uLabelType = QCBOR_TYPE_NONE;

    uErr = QCBORDecode_GetItemsInMap(&DecodeCtx, XX);
    if(uErr != QCBOR_SUCCESS) {
        goto Done;
    }

    pE->Manufacturer = XX[0].val.string;
    pE->uDisplacement = XX[1].val.int64;
    pE->uHorsePower = XX[2].val.int64;
    pE->dDesignedCompresion = XX[3].val.dfnum;
    pE->uNumCylinders = XX[5].val.int64;

    if(XX[4].uDataType == QCBOR_TYPE_TRUE) {
        pE->bTurboCharged = true;
    } else if(XX[4].uDataType == QCBOR_TYPE_FALSE) {
        pE->bTurboCharged = false;
    } else {
        return EngineProtocolerror;
    }


    /* Must check error before referencing pE->uNumCylinders to be sure it
     is valid. If any of the above errored, it won't be valid. */
    uErr = QCBORDecode_GetError(&DecodeCtx);
    if(uErr != QCBOR_SUCCESS) {
        goto Done;
    }

    if(pE->uNumCylinders > MAX_CYLINDERS) {
        return TooManyCylinders;
    }

    QCBORDecode_EnterArrayFromMapSZ(&DecodeCtx, "Cylinders");
    for(int64_t i = 0; i < pE->uNumCylinders; i++) {
        QCBORDecode_GetDouble(&DecodeCtx, &(pE->cylinders[i].uMeasuredCompression));
    }
    QCBORDecode_ExitArray(&DecodeCtx);
    QCBORDecode_ExitMap(&DecodeCtx);

    /* Catch the remainder of errors here */
    uErr = QCBORDecode_Finish(&DecodeCtx);

Done:
    return ConvertError(uErr);
}





/*

 - Match
 - Error
 - No match

 */

QCBORError CheckLabelAndType(const char *szLabel, uint8_t uQCBORType, QCBORItem *pItem)
{
    if(pItem->uLabelType != QCBOR_TYPE_TEXT_STRING) {
        return QCBOR_ERR_NOT_FOUND;
    }

    UsefulBufC Label = UsefulBuf_FromSZ(szLabel);

    if(UsefulBuf_Compare(Label, pItem->label.string)) {
        return QCBOR_ERR_NOT_FOUND;
    }

    if(pItem->uDataType != uQCBORType && uQCBORType != QCBOR_TYPE_ANY) {
        return QCBOR_ERR_UNEXPECTED_TYPE;
    }

    return QCBOR_SUCCESS;
}


EngineDecodeErrors DecodeCylinders(QCBORDecodeContext *pDecodeCtx,
                                   Engine *pE,
                                   const QCBORItem *pItem)
{
    int i = 0;
    QCBORItem Item;

    /* Loop getting all the items in the array */
    do {
        QCBORError uErr;

        uErr = QCBORDecode_GetNext(pDecodeCtx, &Item);
        if(uErr != QCBOR_SUCCESS) {
            return CBORNotWellFormed;
        }
        if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
            return CBORNotWellFormed;
        }

        if(i < MAX_CYLINDERS) {
            pE->cylinders[i].uMeasuredCompression = Item.val.dfnum;
            i++;
        }

    } while (Item.uNextNestLevel == pItem->uNextNestLevel);

    if(i != pE->uNumCylinders) {
        return WrongNumberOfCylinders;
    } else {
        return EngineSuccess;
    }
}



EngineDecodeErrors DecodeEngineBasic(UsefulBufC EncodedEngine, Engine *pE)
{
    QCBORDecodeContext DecodeCtx;

    QCBORDecode_Init(&DecodeCtx, EncodedEngine, 0);// TODO: fill in mode;

    QCBORItem Item;
    QCBORError uErr;
    EngineDecodeErrors uReturn;


    uErr = QCBORDecode_GetNext(&DecodeCtx, &Item);
    if(uErr != QCBOR_SUCCESS) {
        uReturn = CBORNotWellFormed;
        goto Done;
    }
    if(Item.uDataType != QCBOR_TYPE_MAP) {
        uReturn = CBORNotWellFormed;
        goto Done;
    }

    while(1) {
        uErr = QCBORDecode_GetNext(&DecodeCtx, &Item);
        if(uErr != QCBOR_SUCCESS) {
            if(uErr == QCBOR_ERR_NO_MORE_ITEMS) {
                break; /* Non-error exit from the loop */
            } else {
                uReturn = CBORNotWellFormed;
                goto Done;
            }
        }

        uErr = CheckLabelAndType("Manufacturer", QCBOR_TYPE_TEXT_STRING, &Item);
        if(uErr == QCBOR_SUCCESS) {
            pE->Manufacturer = Item.val.string;
            continue;
        } else if(uErr != QCBOR_ERR_NOT_FOUND){
            /* Maunfacturer field missing or badly formed */
            return EngineProtocolerror;
        } /* continue on and try for another match */



        uErr = CheckLabelAndType("NumCylinders", QCBOR_TYPE_INT64, &Item);
        if(uErr == QCBOR_SUCCESS) {
            if(Item.val.int64 > MAX_CYLINDERS) {
                return TooManyCylinders;
            } else {
                pE->uNumCylinders = (uint8_t)Item.val.int64;
                continue;
            }
        } else if(uErr != QCBOR_ERR_NOT_FOUND){
            /* Maunfacturer field missing or badly formed */
            return EngineProtocolerror;
        }

        uErr = CheckLabelAndType("Cylinders", QCBOR_TYPE_ARRAY, &Item);
        if(uErr == QCBOR_SUCCESS) {
            DecodeCylinders(&DecodeCtx, pE, &Item);
            continue;
        } else if(uErr != QCBOR_ERR_NOT_FOUND){
            return EngineProtocolerror;
        }

        uErr = CheckLabelAndType("Displacement", QCBOR_TYPE_INT64, &Item);
        if(uErr == QCBOR_SUCCESS) {
            pE->uDisplacement = Item.val.int64;
            continue;
        } else if(uErr != QCBOR_ERR_NOT_FOUND){
            return EngineProtocolerror;
        }

        uErr = CheckLabelAndType("Horsepower", QCBOR_TYPE_INT64, &Item);
        if(uErr == QCBOR_SUCCESS) {
            pE->uHorsePower = Item.val.int64;
            continue;
        } else if(uErr != QCBOR_ERR_NOT_FOUND){
            return EngineProtocolerror;
        }

        uErr = CheckLabelAndType("DesignedCompression", QCBOR_TYPE_DOUBLE, &Item);
        if(uErr == QCBOR_SUCCESS) {
            pE->dDesignedCompresion = Item.val.dfnum;
            continue;
        } else if(uErr != QCBOR_ERR_NOT_FOUND){
            return EngineProtocolerror;
        }

        uErr = CheckLabelAndType("turbo", QCBOR_TYPE_ANY, &Item);
           if(uErr == QCBOR_SUCCESS) {
               if(Item.uDataType == QCBOR_TYPE_TRUE) {
                   pE->bTurboCharged = true;
               } else if(Item.uDataType == QCBOR_TYPE_FALSE) {
                   pE->bTurboCharged = false;
               } else {
                   return EngineProtocolerror;
               }
               continue;
           } else if(uErr != QCBOR_ERR_NOT_FOUND){
               return EngineProtocolerror;
           }


        /* Some label data item that is not known
         (could just ignore extras data items) */
        return EngineProtocolerror;
    }
    uReturn = EngineSuccess;


Done:
    return uReturn;
}





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

    int x = (int)DecodeEngine(EncodedEngine, &DecodedEngine);
    printf("Engine Decode Result: %d\n", x);


    InDefEncodedEngine = EncodeEngineIndefinteLen(&E, InDefEngineBuffer);

    printf("Indef Engine Encoded in %zu bytes\n", InDefEncodedEngine.len);

    x = (int)DecodeEngine(InDefEncodedEngine, &DecodedEngine);
    printf("Indef Engine Decode Result: %d\n", x);

    if(!EngineCompare(&E, &DecodedEngine)) {
        printf("decode comparison fail\n");
    }


    x = (int)DecodeEngineBasic(EncodedEngine, &DecodedEngine);
    printf("Engine Basic Decode Result: %d\n", x);

    if(!EngineCompare(&E, &DecodedEngine)) {
        printf("decode comparison fail\n");
    }


    x = (int)DecodeEngineBasic(InDefEncodedEngine, &DecodedEngine);
    printf("Indef Engine Basic Decode Result: %d\n", x);

    if(!EngineCompare(&E, &DecodedEngine)) {
        printf("indef decode comparison fail\n");
    }

    x = (int)DecodeEngineXX(EncodedEngine, &DecodedEngine);
    printf("Efficient Engine Basic Decode Result: %d\n", x);

    if(!EngineCompare(&E, &DecodedEngine)) {
        printf("effcieit decode comparison fail\n");
    }
}
