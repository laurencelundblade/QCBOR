//
//  basic_test.c
//  QCBOR
//
//  Created by Laurence Lundblade on 9/13/18.
//  Copyright © 2018 Laurence Lundblade. All rights reserved.
//

#include "basic_test.h"

#include "qcbor.h"


int basic_test_one()
{
    MakeUsefulBufOnStack(Storage, 512);
    QCBOREncodeContext EC;
    
    QCBOREncode_Init(&EC, Storage);
    
    QCBOREncode_AddBool(&EC, true);
    
    EncodedCBOR Encoded;
    if(QCBOREncode_Finish2(&EC, &Encoded)) {
        return -3;
    }
    
    
    
    QCBORDecodeContext DC;
    QCBORItem Item;
    QCBORDecode_Init(&DC, Encoded.Bytes, QCBOR_DECODE_MODE_NORMAL);
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_TRUE) {
        return -1;
    }
    
    if(QCBORDecode_Finish(&DC)) {
        return -2;
    }
    
    return 0;
}
