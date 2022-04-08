//
//  ub-example.c
//  QCBOR
//
//  Created by Laurence Lundblade on 4/8/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "ub-example.h"

#include "UsefulBuf.h"


/*
 A large number of the security issues with C code come from mistakes
 made with a pointer and length for a buffer or some binary data.
 UsefulBuf adopts a convention that a pointer and length *always*
 go together to migitigate this.  With UsefulBuf there are never
 pointers without lengths so you always know how big the buffer
 or the data is.

 C99 allows passing structures so a structure is used. Compilers
 are smart these days so the object code produced is no different
 than passing two separate parameters. Passing structures also
 makes the interfaces prettier. Assignments of structures also
 can make code prettier.

 There are a bunch of (tested!) functions to manipulate UsefulBuf's so
 code using it may have no pointer manipulation at all!

 In this example the buffers that are filled in with data
 are const and the ones that are to-be-filled in are not
 const. Keeping const distinct from non-const is helpful
 when reading the code and helps avoid some coding mistakes.
 See this:
 https://stackoverflow.com/questions/117293/use-of-const-for-function-parameters

 This contrived example copies data from input to output
 expanding bytes with the value 'x' to 'xx'.

 Input -- This is the pointer and length of the input, the
 bytes to copy. Note that UsefulBufC.ptr is a const void *
 indicates that input data won't be changed by this function.
 There is a "C" in UsefulBufC to indicate the value is const.
 The length here is the length of the valid input data. Note
 also that the parameter Input is const, so this is fully
 const and clearly an [in] parameter.

 Output -- This is a pointer and length of
 the memory to used to store the output. The correct length
 here is critical for code security. Note that  UsefulBuf.ptr
 is void *, it is not const indicating data can be written to
 it. Note that the parameter itself *is* const indicating
 that the code below will not point this to some other buffer
 or change the length and clearly marked as an [in] parameter.

 Output -- This is the interesting and unusual one. To stay
 consistent with always paring and a length and for
 a pointer to valid data to always be const, this is returned as
 a UsefulBufC. Note that the parameter is a pointer to a
 UsefulBufC, a *place* to return a UsefulBufC.

 In this case and most cases the pointer in Output->ptr
 will be the same as OutputBuffer.ptr. This may seem
 redundant, but there's a few reasons for it. First,
 is the goal of always pairing a pointer and a length.
 Second is being more strict with constness. Third
 is the code hygene and clarity of having
 variables for to-be-filled buffers be distinct from those
 containing valid data. Fourth, there are no [in,out]
 parameters, only [in] parameters and [out] parameters
 (the to-be-filled-in buffer is considered an [in]
 parameter).

 Note that the compiler will be smart about all
 this and should generate pretty much the same code
 as for a traditional interface with the
 length parameter. On x86 with gcc-11 and no stack guards,
 the UB code is 81 bytes and the traditional code is 77 bytes.

 This supports computing of the would-be output
 without actually doing any outputing by making
 the OutputBuffer have a NULL pointer and a very
 large length, e.g., {NULL, SIZE_MAX}.

 */
int
ExpandUB(const UsefulBufC   Input,
         const UsefulBuf    OutputBuffer,
         UsefulBufC        *Output)
{
    size_t nInputPosition;
    size_t nOutputPosition;

    nOutputPosition = 0;

    /* Loop over all the bytes in Input */
    for(nInputPosition = 0; nInputPosition < Input.len; nInputPosition++) {
        const uint8_t nInputByte = ((uint8_t*)Input.ptr)[nInputPosition];

        /* Copy every byte */
        if(OutputBuffer.ptr != NULL) {
            ((uint8_t *)OutputBuffer.ptr)[nOutputPosition] = nInputByte;
        }
        nOutputPosition++;
        if(nOutputPosition >= OutputBuffer.len) {
            return -1l;
        }

        /* Double output 'x' because that is what this contrived example does */
        if(nInputByte== 'x') {
            if(OutputBuffer.ptr != NULL) {
                ((uint8_t *)OutputBuffer.ptr)[nOutputPosition] = 'x';
            }
            nOutputPosition++;
            if(nOutputPosition >= OutputBuffer.len) {
                return -1l;
            }
        }
    }

    *Output = (UsefulBufC){OutputBuffer.ptr, nOutputPosition};

    return 0; /* success */
}


/* This is the more tradional way to implement this. */
int ExpandTraditional(const uint8_t  *pInputPointer,
                       const size_t    uInputLength,
                       uint8_t        *pOutputBuffer,
                       const size_t    uOutputBufferLength,
                       size_t         *puOutputLength)
{
    size_t nInputPosition;
    size_t nOutputPosition;

    nOutputPosition = 0;

    /* Loop over all the bytes in Input */
    for(nInputPosition = 0; nInputPosition < uInputLength; nInputPosition++) {
        const uint8_t nInputByte = ((uint8_t*)pInputPointer)[nInputPosition];

        /* Copy every byte */
        if(pOutputBuffer != NULL) {
            ((uint8_t *)pOutputBuffer)[nOutputPosition] = nInputByte;
        }
        nOutputPosition++;
        if(nOutputPosition >= uOutputBufferLength) {
            return -1l;
        }

        /* Double output 'x' because that is what this contrived example does */
        if(nInputByte== 'x') {
            if(pOutputBuffer != NULL) {
                ((uint8_t *)pOutputBuffer)[nOutputPosition] = 'x';
            }
            nOutputPosition++;
            if(nOutputPosition >= uOutputBufferLength) {
                return -1l;
            }
        }
    }

   *puOutputLength = nOutputPosition;

    return 0; /* success */
}


/*
 Here's an example of going from a traditional interface
 interface to a UsefulBuf interface.
 */
int ExpandTraditionalAdapted(const uint8_t  *pInputPointer,
                             size_t          uInputLength,
                             uint8_t        *pOutputBuffer,
                             size_t          uOutputBufferLength,
                             size_t         *puOutputLength)
{
    UsefulBufC  Input;
    UsefulBuf   OutputBuffer;
    UsefulBufC  Output;
    int         nReturn;

    Input = (UsefulBufC){pInputPointer, uInputLength};
    OutputBuffer = (UsefulBuf){pOutputBuffer, uOutputBufferLength};

    nReturn = ExpandUB(Input, OutputBuffer, &Output);

    *puOutputLength = Output.len;

    return nReturn;
}


/* Here's an example for going from a UsefulBuf interface
 to a traditional interface. */
int
ExpandUBAdapted(const UsefulBufC   Input,
                const UsefulBuf    OutputBuffer,
                UsefulBufC        *Output)
{
    Output->ptr = OutputBuffer.ptr;

    return ExpandTraditional(Input.ptr, Input.len,
                                OutputBuffer.ptr, OutputBuffer.len,
                               &(Output->len));
}



#define INPUT "xyz123xyz"

int32_t RunUsefulBufExample()
{
   /* ------------ UsefulBuf examples ------------- */
   UsefulBufC Input = UsefulBuf_FROM_SZ_LITERAL(INPUT);

   /* This macros makes a 20 byte buffer on the stack. It also makes
    * a UsefulBuf on the stack. It sets up the UsefulBuf to point to
    * the 20 byte buffer and sets it's length to 20 bytes. This
    * is the empty, to-be-filled in memory for the output. It is not
    * const. */
   MakeUsefulBufOnStack(OutBuf, sizeof(INPUT) * 2);

   /* This is were the pointer and the length of the completed output
    * will be placed. Output.ptr is a pointer to const bytes. */
   UsefulBufC           Output;

   ExpandUB(Input, OutBuf, &Output);

   ExpandUBAdapted(Input, OutBuf, &Output);



   /* ------ Get Size example  -------- */
   ExpandUB(Input, (UsefulBuf){NULL, SIZE_MAX}, &Output);

   /* Size is in Output.len */



   /* ---------- Traditional examples (for comparison) --------- */
   uint8_t puBuffer[sizeof(INPUT) * 2];
   size_t  uOutputSize;

   ExpandTraditional((const uint8_t *)INPUT, sizeof(INPUT),
                     puBuffer, sizeof(puBuffer),
                     &uOutputSize);


   ExpandTraditionalAdapted((const uint8_t *)INPUT, sizeof(INPUT),
                            puBuffer, sizeof(puBuffer),
                           &uOutputSize);

   return 0;
}
