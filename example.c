/* =========================================================================
   example.c -- Example code for QCBOR

   Copyright (c) 2020, Laurence Lundblade. All rights reserved.

   SPDX-License-Identifier: BSD-3-Clause

   See BSD-3-Clause license in README.md

   Created on 6/30/2020
  ========================================================================== */

#include <stdio.h>
#include "example.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"


#define MAX_CYLINDERS 16

/**
 The data structure representing a car engine that is encoded and
 decoded in this example.
 */
typedef struct
{
   UsefulBufC Manufacturer;
   int64_t    uDisplacement;
   int64_t    uHorsePower;
   double     dDesignedCompresion;
   int64_t    uNumCylinders;
   bool       bTurboCharged;
   struct {
      double uMeasuredCompression;
   } cylinders[MAX_CYLINDERS];
} CarEngine;


/**
 @brief Initialize the Engine data structure with values to encode/decode.

 @param[out] pE   The Engine structure to fill in
 */
void EngineInit(CarEngine *pE)
{
   pE->Manufacturer        = UsefulBuf_FROM_SZ_LITERAL("Porsche");
   pE->uDisplacement       = 3296;
   pE->uHorsePower         = 210;
   pE->dDesignedCompresion = 9.1;
   pE->uNumCylinders       = 6;
   pE->bTurboCharged       = false;

   pE->cylinders[0].uMeasuredCompression = 9.0;
   pE->cylinders[1].uMeasuredCompression = 9.2;
   pE->cylinders[2].uMeasuredCompression = 8.9;
   pE->cylinders[3].uMeasuredCompression = 8.9;
   pE->cylinders[4].uMeasuredCompression = 9.1;
   pE->cylinders[5].uMeasuredCompression = 9.0;
}


/**
 @brief Compare two Engine structure for equality.

 @param[in] pE1  First Engine to compare.
 @param[in] pE2  Second Engine to compare.

 @retval Return @c true if the two Engine data structures are exactly the
 same.
 */
bool EngineCompare(CarEngine *pE1, CarEngine *pE2)
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


#ifndef EXAMPLE_DISABLE_DEFINITE_LENGTH_ENCODE
/**
 @brief Encode an initialized Engine data structure in CBOR.

 @param[in] pEngine  The data structure to encode.
 @param[in] Buffer   Pointer and length of buffer to output to.

 @return  The pointer and length of the encoded CBOR or
          @ref NULLUsefulBufC on error.

 This is a simple CBOR encoding example. It outputs the Engine data
 structure as a map of label-value pairs as well as an array of
 floating point values.

 @c Buffer must be big enough to hold the output. If it is not @ref
 NULLUsefulBufC will be returned. @ref @ref NULLUsefulBufC will be
 returned for any other encoding errors.

 This encoding will use definite CBOR lengths. Definite lengths are
 preferred in CBOR. See EncodeEngineIndefinteLen() that encodes using
 indefinite lengths.
 */
UsefulBufC EncodeEngineDefiniteLength(const CarEngine *pEngine, UsefulBuf Buffer)
{
    /* Initialize the encoder with the buffer big enough to hold the
       expected output.  If it is too small, QCBOREncode_Finish() will
       return an error. */
    QCBOREncodeContext EncodeCtx;
    QCBOREncode_Init(&EncodeCtx, Buffer);

    /* Proceed to output all the items, letting the internal error
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
    QCBOREncode_AddBoolToMap(&EncodeCtx, "Turbo", pEngine->bTurboCharged);
    QCBOREncode_CloseMap(&EncodeCtx);

    /* Get the pointer and length of the encoded output. If there was
       any error it will be returned here. */
    UsefulBufC EncodedCBOR;
    QCBORError uErr;
    uErr = QCBOREncode_Finish(&EncodeCtx, &EncodedCBOR);
    if(uErr != QCBOR_SUCCESS) {
       return NULLUsefulBufC;
    } else {
       return EncodedCBOR;
    }
}
#endif /* EXAMPLE_DISABLE_DEFINITE_LENGTH_ENCODE */




#ifndef EXAMPLE_DISABLE_INDEFINITE_LENGTH_ENCODE_ENCODE
/**
 @brief Encode an initialized Engine data structure using indefinite lengths.

 @param[in] pEngine  The data structure to encode.
 @param[in] Buffer   Pointer and length of buffer to output to.

 @return The pointer and length of the encoded CBOR or
         @ref NULLUsefulBufC on error.

 This is virtually the same as EncodeEngineDefiniteLength(). The
 encoded CBOR is slightly different as the map and array use
 indefinite lengths, rather than definite lengths.

 A definite length array is encoded as an integer indicating the
 number of items in it. An indefinite length array is encoded as an
 opening byte, the items in it and a "break" byte to end
 it. Indefinite length arrays and maps are easier to encode, but
 harder to decode.

 The advantage of this implementation is that the encoding side will
 be a little less object code. (Eventually QCBOR will an ifdef to
 disable definite length encoding and the object code will be even
 smaller).  However, note that the encoding implementation for a
 protocol is just about always much smaller than the decoding
 implementation and that code savings for use of indefinite lengths is
 relatively small.
 */
UsefulBufC EncodeEngineIndefinteLen(const CarEngine *pEngine, UsefulBuf Buffer)
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
    QCBOREncode_AddBoolToMap(&EncodeCtx, "Turbo", pEngine->bTurboCharged);
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
#endif /* EXAMPLE_DISABLE_INDEFINITE_LENGTH_ENCODE */


/**
 Error results when decoding an Engine data structure.
 */
typedef enum  {
    EngineSuccess,
    CBORNotWellFormed,
    TooManyCylinders,
    EngineProtocolerror,
    WrongNumberOfCylinders
} EngineDecodeErrors;


/**
 Convert @ref QCBORError to @ref EngineDecodeErrors.
 */
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


#ifndef EXAMPLE_DISABLE_SPIFFY_DECODE
/**
 @brief Simplest engine decode using spiffy decode features.

 @param[in] EncodedEngine  Pointer and length of CBOR-encoded engine.
 @param[out] pE            The structure filled in from the decoding.

 @return The decode error or success.

 This decodes the CBOR into the engine structure.

 As QCBOR automatically supports both definite and indefinite maps and
 arrays, this will decode either.

 This uses QCBOR's spiffy decode, so the implementation is simplest
 and closely parallels the encode implementation in
 EncodeEngineDefiniteLength().

 See two other ways to implement decoding in
 DecodeEngineSpiffyFaster() and DecodeEngineBasic().

 This version of the decoder has the simplest implementation, but
 pulls in more code from the QCBOR library.  This version uses the
 most CPU cycles because it scans the all the CBOR each time a data
 item is decoded. The CPU cycles used for a data structure as small as
 this is probably insignificant. CPU use for this style of decode is
 probably only a factor on slow CPUs with big CBOR inputs.
 */
EngineDecodeErrors DecodeEngineSpiffy(UsefulBufC EncodedEngine, CarEngine *pE)
{
    QCBORError uErr;
    QCBORDecodeContext DecodeCtx;

    QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&DecodeCtx, NULL);
    QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "Manufacturer", &(pE->Manufacturer));
    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Displacement", &(pE->uDisplacement));
    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Horsepower", &(pE->uHorsePower));
    QCBORDecode_GetDoubleInMapSZ(&DecodeCtx, "DesignedCompression", &(pE->dDesignedCompresion));
    QCBORDecode_GetBoolInMapSZ(&DecodeCtx, "Turbo", &(pE->bTurboCharged));

    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "NumCylinders", &(pE->uNumCylinders));

    /* Must check error before referencing pE->uNumCylinders to be
       sure it is valid. If any of the above errored, it won't be
       valid. */
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

#endif /* EXAMPLE_DISABLE_SPIFFY_DECODE */



#ifndef EXAMPLE_DISABLE_SPIFFY_DECODE_FAST
/**
 @brief Decode an Engine structure with the faster spiffy decode features.

 @param[in] EncodedEngine  Pointer and length of CBOR-encoded engine.
 @param[out] pE            The structure filled in from the decoding.

 @return The decode error or success.

 This decodes the same as DecodeEngineSpiffy(), but uses different
 spiffy decode features.

 This version uses QCBORDecode_GetItemsInMap() which uses less CPU
 cycles because all the items except the array are pulled out of the
 map in one pass, rather than having to decode the whole map for each
 decoded item. This also pulls in less object code from the QCBOR
 library.

 See also DecodeEngineAdvanced() and DecodeEngineBasic().
*/
EngineDecodeErrors DecodeEngineSpiffyFaster(UsefulBufC EncodedEngine, CarEngine *pE)
{
    QCBORError uErr;
    QCBORDecodeContext DecodeCtx;

    QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&DecodeCtx, NULL);

    QCBORItem EngineItems[7];
    EngineItems[0].uLabelType = QCBOR_TYPE_TEXT_STRING;
    EngineItems[0].label.string = UsefulBuf_FROM_SZ_LITERAL("Manufacturer");
    EngineItems[0].uDataType = QCBOR_TYPE_TEXT_STRING;

    EngineItems[1].uLabelType = QCBOR_TYPE_TEXT_STRING;
    EngineItems[1].label.string = UsefulBuf_FROM_SZ_LITERAL("Displacement");
    EngineItems[1].uDataType = QCBOR_TYPE_INT64;

    EngineItems[2].uLabelType = QCBOR_TYPE_TEXT_STRING;
    EngineItems[2].label.string = UsefulBuf_FROM_SZ_LITERAL("Horsepower");
    EngineItems[2].uDataType = QCBOR_TYPE_INT64;

    EngineItems[3].uLabelType = QCBOR_TYPE_TEXT_STRING;
    EngineItems[3].label.string = UsefulBuf_FROM_SZ_LITERAL("DesignedCompression");
    EngineItems[3].uDataType = QCBOR_TYPE_DOUBLE;

    EngineItems[4].uLabelType = QCBOR_TYPE_TEXT_STRING;
    EngineItems[4].label.string = UsefulBuf_FROM_SZ_LITERAL("Turbo");
    EngineItems[4].uDataType = QCBOR_TYPE_ANY;

    EngineItems[5].uLabelType = QCBOR_TYPE_TEXT_STRING;
    EngineItems[5].label.string = UsefulBuf_FROM_SZ_LITERAL("NumCylinders");
    EngineItems[5].uDataType = QCBOR_TYPE_INT64;

    EngineItems[6].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&DecodeCtx, EngineItems);
    uErr = QCBORDecode_GetError(&DecodeCtx);
    if(uErr != QCBOR_SUCCESS) {
        goto Done;
    }

    pE->Manufacturer = EngineItems[0].val.string;
    pE->uDisplacement = EngineItems[1].val.int64;
    pE->uHorsePower = EngineItems[2].val.int64;
    pE->dDesignedCompresion = EngineItems[3].val.dfnum;
    pE->uNumCylinders = EngineItems[5].val.int64;

    if(EngineItems[4].uDataType == QCBOR_TYPE_TRUE) {
        pE->bTurboCharged = true;
    } else if(EngineItems[4].uDataType == QCBOR_TYPE_FALSE) {
        pE->bTurboCharged = false;
    } else {
        return EngineProtocolerror;
    }


    /* Must check error before referencing pE->uNumCylinders to be
       sure it is valid. If any of the above errored, it won't be
       valid. */
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

#endif /* EXAMPLE_DISABLE_SPIFFY_DECODE_FAST */


#ifndef EXAMPLE_DISABLE_BASIC_DECODE
/**
 @brief Check the type and lable of an item.

 @param[in] szLabel     The expected string label.
 @param[in] uQCBORType  The expected type or @c QCBOR_TYPE_ANY.
 @param[in] pItem       The item to check.

 @retval QCBOR_ERR_LABEL_NOT_FOUND  The label doesn't match.
 @retval QCBOR_ERR_UNEXPECTED_TYPE  The label matches, but the type is
                                    not as expected.
 @retval QCBOR_SUCCESS              Both label and type match.
 */
QCBORError CheckLabelAndType(const char *szLabel, uint8_t uQCBORType, const QCBORItem *pItem)
{
    if(pItem->uLabelType != QCBOR_TYPE_TEXT_STRING) {
        return QCBOR_ERR_LABEL_NOT_FOUND;
    }

    UsefulBufC Label = UsefulBuf_FromSZ(szLabel);

    if(UsefulBuf_Compare(Label, pItem->label.string)) {
        return QCBOR_ERR_LABEL_NOT_FOUND;
    }

    if(pItem->uDataType != uQCBORType && uQCBORType != QCBOR_TYPE_ANY) {
        return QCBOR_ERR_UNEXPECTED_TYPE;
    }

    return QCBOR_SUCCESS;
}


/**
 @brief Decode the array of engine cylinders.

 @param[in] pDecodeCtx  The decode context from which to get items.
 @param[out] pE         The structure filled in from the decoding.
 @param[in] pItem       The data item that is the start of the array.

 @return Either @ref EngineSuccess or an error.

 This always consumes the whole array. If it has the wrong number of
 items in it, an error is returned.
 */
EngineDecodeErrors DecodeCylinders(QCBORDecodeContext *pDecodeCtx,
                                   CarEngine          *pE,
                                   const QCBORItem    *pItem)
{
    int i = 0;
    QCBORItem Item;

    /* Loop getting all the items in the array. This uses nesting
       level to detect the end so it works for both definite and
       indefinite length arrays. */
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


/**
 @brief Engine decode without spiffy decode.

 @param[in] EncodedEngine  Pointer and length of CBOR-encoded engine.
 @param[out] pE            The structure filled in from the decoding.

 @return The decode error or success.

 This is the third implementation of engine decoding, again
 implementing the same functionality as DecodeEngineSpiffy() and
 DecodeEngineSpiffyFaster().

 This version of the deocde is the most complex, but uses
 significantly less code (2-3KB less on 64-bit Intel) from the QCBOR
 library.  It is also the most CPU-efficient since it does only one
 pass through the CBOR.
*/
EngineDecodeErrors DecodeEngineBasic(UsefulBufC EncodedEngine, CarEngine *pE)
{
    QCBORDecodeContext DecodeCtx;

    QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);

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
        } else if(uErr != QCBOR_ERR_LABEL_NOT_FOUND){
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
        } else if(uErr != QCBOR_ERR_LABEL_NOT_FOUND){
            /* NumCylinders field missing or badly formed */
            return EngineProtocolerror;
        } /* continue on and try for another match */

        uErr = CheckLabelAndType("Cylinders", QCBOR_TYPE_ARRAY, &Item);
        if(uErr == QCBOR_SUCCESS) {
            DecodeCylinders(&DecodeCtx, pE, &Item);
            continue;
        } else if(uErr != QCBOR_ERR_LABEL_NOT_FOUND){
            return EngineProtocolerror;
        }

        uErr = CheckLabelAndType("Displacement", QCBOR_TYPE_INT64, &Item);
        if(uErr == QCBOR_SUCCESS) {
            pE->uDisplacement = Item.val.int64;
            continue;
        } else if(uErr != QCBOR_ERR_LABEL_NOT_FOUND){
            return EngineProtocolerror;
        }

        uErr = CheckLabelAndType("Horsepower", QCBOR_TYPE_INT64, &Item);
        if(uErr == QCBOR_SUCCESS) {
            pE->uHorsePower = Item.val.int64;
            continue;
        } else if(uErr != QCBOR_ERR_LABEL_NOT_FOUND){
            return EngineProtocolerror;
        }

        uErr = CheckLabelAndType("DesignedCompression", QCBOR_TYPE_DOUBLE, &Item);
        if(uErr == QCBOR_SUCCESS) {
            pE->dDesignedCompresion = Item.val.dfnum;
            continue;
        } else if(uErr != QCBOR_ERR_LABEL_NOT_FOUND){
            return EngineProtocolerror;
        }

        uErr = CheckLabelAndType("Turbo", QCBOR_TYPE_ANY, &Item);
        if(uErr == QCBOR_SUCCESS) {
            if(Item.uDataType == QCBOR_TYPE_TRUE) {
                pE->bTurboCharged = true;
            } else if(Item.uDataType == QCBOR_TYPE_FALSE) {
                pE->bTurboCharged = false;
            } else {
                return EngineProtocolerror;
            }
            continue;
        } else if(uErr != QCBOR_ERR_LABEL_NOT_FOUND){
            return EngineProtocolerror;
        }

        /* Some label data item that is not known (could just ignore
           extras data items) */
        return EngineProtocolerror;
    }
    uReturn = EngineSuccess;

    /* Catch the remainder of errors here */
    uErr = QCBORDecode_Finish(&DecodeCtx);
    if(uErr) {
        uReturn = ConvertError(uErr);
    }



Done:
    return uReturn;
}

#endif /* EXAMPLE_DISABLE_BASIC_DECODE */


int32_t RunQCborExample()
{
   CarEngine               E, DecodedEngine;
   MakeUsefulBufOnStack(   EngineBuffer, 300);
   UsefulBufC              EncodedEngine;

   MakeUsefulBufOnStack(   InDefEngineBuffer, 300);
   UsefulBufC              InDefEncodedEngine;

   EngineDecodeErrors      uErr;

   EngineInit(&E);

#ifndef EXAMPLE_DISABLE_DEFINITE_LENGTH_ENCODE
   EncodedEngine = EncodeEngineDefiniteLength(&E, EngineBuffer);
   printf("Definite Length Engine Encoded in %zu bytes\n", EncodedEngine.len);
#endif /* EXAMPLE_DISABLE_DEFINITE_LENGTH_ENCODE */


#ifndef EXAMPLE_DISABLE_INDEFINITE_LENGTH_ENCODE_ENCODE
   InDefEncodedEngine = EncodeEngineIndefinteLen(&E, InDefEngineBuffer);
   printf("Indef Engine Encoded in %zu bytes\n", InDefEncodedEngine.len);
#endif /* EXAMPLE_DISABLE_INDEFINITE_LENGTH_ENCODE_ENCODE */


#ifndef EXAMPLE_DISABLE_SPIFFY_DECODE
   uErr = DecodeEngineSpiffy(EncodedEngine, &DecodedEngine);
   printf("Spiffy Engine Decode Result: %d\n", uErr);

   if(!EngineCompare(&E, &DecodedEngine)) {
      printf("Spiffy Engine Decode comparison fail\n");
   }
#endif /* EXAMPLE_DISABLE_SPIFFY_DECODE */

#ifndef EXAMPLE_DISABLE_SPIFFY_DECODE_FAST
   uErr = DecodeEngineSpiffyFaster(EncodedEngine, &DecodedEngine);
   printf("Faster Spiffy Engine Decode Result: %d\n", uErr);

   if(!EngineCompare(&E, &DecodedEngine)) {
      printf("Faster Spiffy Engine Decode comparison fail\n");
   }
#endif /* EXAMPLE_DISABLE_SPIFFY_DECODE_FAST */

#ifndef EXAMPLE_DISABLE_BASIC_DECODE
   uErr = DecodeEngineBasic(EncodedEngine, &DecodedEngine);
   printf("Engine Basic Decode Result: %d\n", uErr);

   if(!EngineCompare(&E, &DecodedEngine)) {
      printf("Engine Basic Decode comparison fail\n");
   }
#endif /* EXAMPLE_DISABLE_BASIC_DECODE */

   printf("\n");

   return 0;
}
