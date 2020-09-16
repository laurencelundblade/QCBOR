#  Try Spiffy Decode

A major new version of QCBOR has Spiffy Decode which makes it much easier to 
implement CBOR decoding.

The decoding implementation of a protocol looks like the encoding implementation:

     /* Encode */
     QCBOREncode_Init(&EncodeCtx, Buffer);
     QCBOREncode_OpenMap(&EncodeCtx);
     QCBOREncode_AddTextToMap(&EncodeCtx, "Manufacturer", pE->Manufacturer);
     QCBOREncode_AddInt64ToMap(&EncodeCtx, "Displacement", pE->uDisplacement);
     QCBOREncode_AddInt64ToMap(&EncodeCtx, "Horsepower", pE->uHorsePower);
     QCBOREncode_CloseMap(&EncodeCtx);
     uErr = QCBOREncode_Finish(&EncodeCtx, &EncodedEngine);
  
     /* Decode */
     QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);
     QCBORDecode_EnterMap(&DecodeCtx);
     QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "Manufacturer", &(pE->Manufacturer));
     QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Displacement", &(pE->uDisplacement));
     QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Horsepower", &(pE->uHorsePower));
     QCBORDecode_ExitMap(&DecodeCtx);
     uErr = QCBORDecode_Finish(&DecodeCtx);

With the previous decoding API (which is still supported), the decode implementation 
is 5-10 times longer.

While the QCBOR library is larger, it reduces the object code needed to call it by a lot,
so if you have to decode multiple maps, overall object code is likely to go down.

While this new version is backwards compatible, it is a large change so it is not
yet merged into the QCBOR master. It needs more testing before that happens.

This new version is in SpiffyDecode branch so you have to explicitly go and get that branch.

This version also improves tag handling a lot, adds duplicate map label detection and fixes
some bugs with CBOR that is a combination of definite and indefinite lengths.


