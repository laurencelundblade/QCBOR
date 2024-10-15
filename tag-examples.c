//
//  tag-examples.c
//  QCBOR
//
//  Created by Laurence Lundblade on 10/7/24.
//  Copyright © 2024 Laurence Lundblade. All rights reserved.
//

#include "tag-examples.h"
#include "qcbor/qcbor_tag_decode.h"
#include <stdio.h>

// The CBOR to decode
static const uint8_t spAddrs[] = {
    0xD8, 0x34, 0x44, 0xC0, 0x00, 0x02, 0x01

};

#define CBOR_TAG_IPV4 52
#define CBOR_TAG_IPV6 54



#ifndef QCBOR_DISABLE_TAGS


#define USER_TYPE_IPV4_ADDR 130
#define USER_TYPE_IPV6_ADDR 131

static QCBORError
IPAddrDecodeCallBack(QCBORDecodeContext *pDecodeCtx,
                     void               *pTagDecodersContext,
                     uint64_t            uTagNumber,
                     QCBORItem          *pDecodedItem)
{
    (void)pTagDecodersContext;
    (void)pDecodeCtx;

    if(pDecodedItem->uDataType != QCBOR_TYPE_BYTE_STRING) {
        return QCBOR_ERR_UNEXPECTED_TYPE;
    }

    switch(uTagNumber) {
        case CBOR_TAG_IPV4:
            if(pDecodedItem->val.string.len != 4) {
                return QCBOR_ERR_BAD_TAG_CONTENT;
            }
            pDecodedItem->uDataType = USER_TYPE_IPV4_ADDR;
            break;

        case CBOR_TAG_IPV6:
            if(pDecodedItem->val.string.len != 6) {
                return QCBOR_ERR_BAD_TAG_CONTENT;
            }
            pDecodedItem->uDataType = USER_TYPE_IPV6_ADDR;
            break;

        default:
            return QCBOR_ERR_UNEXPECTED_TAG_NUMBER;
    }

    return QCBOR_SUCCESS;
}

const struct QCBORTagDecoderEntry Example_TagDecoderTable[] = {
    {CBOR_TAG_IPV4, IPAddrDecodeCallBack},
    {CBOR_TAG_IPV6, IPAddrDecodeCallBack},
    {CBOR_TAG_INVALID64, NULL}
};




void 
Example_DecodeIPAddrWithCallBack(void)
{
    QCBORDecodeContext DCtx;
    QCBORItem          Item;

    QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spAddrs), 0);
    QCBORDecode_InstallTagDecoders(&DCtx, Example_TagDecoderTable, NULL);
    QCBORDecode_VGetNext(&DCtx, &Item);
    QCBORDecode_Finish(&DCtx);

    if(QCBORDecode_GetError(&DCtx)) {
        printf("Fail\n");
    } else {
        printf("%d\n", Item.uDataType);
    }
}

#endif /* ! QCBOR_DISABLE_TAGS */



/* If bMustBeTag is true, the input to decode must start with
 * a tag number indicating an IP address. The type of IP address
 * is returned in puIPVersion.
 *
 * if bMustBeTag is false, the input must not have a tag
 * number. It is just the tag content that is defined for
 * for IP Addresses. puIPVersion because an input parameter
 * and indicates the type of IP address.
 */
void
GetIPAddr(QCBORDecodeContext *pDecodeCtx,
          bool                bMustBeTag,
          uint8_t            *puIPVersion,
          UsefulBufC         *pAddr)
{
    QCBORItem  Item;
    size_t     nExpectedLen;
    QCBORError uErr;

#ifndef QCBOR_DISABLE_TAGS
    if(bMustBeTag) {
        uint64_t   uTagNumber;

        QCBORDecode_GetNextTagNumber(pDecodeCtx, &uTagNumber);
        switch(uTagNumber) {
            case CBOR_TAG_IPV4:
                *puIPVersion = 4;
                break;

            case CBOR_TAG_IPV6:
                *puIPVersion = 6;
                break;

            case CBOR_TAG_INVALID64:
                if(bMustBeTag) {
                    uErr = QCBOR_ERR_BAD_TAG_CONTENT;
                }

            default:
                uErr = QCBOR_ERR_UNEXPECTED_TYPE;
                goto Done;
        }
    }
#endif /* ! QCBOR_DISABLE_TAGS */


    if(*puIPVersion == 4) {
        nExpectedLen = 4;
    } else if(*puIPVersion == 6) {
        nExpectedLen = 16;
    } else  {
        uErr = 150; // TODO:
        goto Done;
    }

    QCBORDecode_VGetNext(pDecodeCtx, &Item);
    if(QCBORDecode_GetError(pDecodeCtx)) {
        return;
    }

    if(Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        uErr = QCBOR_ERR_BAD_TAG_CONTENT;
        goto Done;
    }

    if(Item.val.string.len != nExpectedLen) {
        uErr = QCBOR_ERR_BAD_TAG_CONTENT;
        goto Done;
    }

    uErr = QCBOR_SUCCESS;
    *pAddr = Item.val.string;

Done:
    QCBORDecode_SetError(pDecodeCtx, uErr);
}


void 
Example_DecodeIPAddrWithGet(void)
{
    QCBORDecodeContext DCtx;
    uint8_t            uType;
    UsefulBufC         Addr;

    QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spAddrs), 0);
    GetIPAddr(&DCtx, true, &uType, &Addr);
    QCBORDecode_Finish(&DCtx);

    if(QCBORDecode_GetError(&DCtx)) {
        printf("Fail\n");
    } else {
        printf("%d\n", uType);
    }
}




int32_t
RunTagExamples(void)
{
#ifndef QCBOR_DISABLE_TAGS
    Example_DecodeIPAddrWithCallBack();
#endif /* ! QCBOR_DISABLE_TAGS */
    Example_DecodeIPAddrWithGet();

    return 0;
}
