This is a tour of QCBOR's byte string encoding features, particularly
those that don't fit in a single buffer.

# Encoding a simple string

The simple case is encoding a byte string in a single buffer of
known length. Generally,
it will fit in a fixed length output buffer that holds the entire encoded output
and doesn't create a requirement for streaming or segmenting. The API is:

    QCBOREncode_AddBytes()
    
If the encoder is in streaming mode, presumably for other reasons
than this string, efficiency from reduced copying can be gained with:
    
    QCBOREncode_AddStreamedBytes()
    
If you want to obtain a buffer to pass to some function
so it can write directly into the output buffer use:

    QCBOREncode_OpenBytes()
    QCBOREncode_OpenSizedBytes()
       
For example, to have something like a signing operation write
the signature directly to the output buffer, avoiding the use
of a temporary buffer, these can be used.       

    
# Encoding a string that is in segments

In the rest of the cases discussed here, the string doesn't exist in a single buffer. 
It is probably constructed on-the-fly one segment at a time.
For example, the output of block-by-block AES encryption.
This segmenting might also be used to avoid allocating big blocks of memory.

## String fits in the output buffer

In this case, the encoder is not in streaming mode, 
so the string has to fit in the output buffer.

QCBOR can encode a string in segments as a single
definite-length string with these:

       QCBOREncode_OpenSizedBytes()
       QCBOREncode_OpenBytes()
           
QCBOR can also encode this as an indefinite-length string, but
that is generally not preferrable because it is harder to
decode and some receivers can't decode them.

       QCBOREncode_OpenIndefiniteLengthBytes()

### Byte string wrapping

Some protocols required encoded CBOR be wrapped in a 
byte string. QCBOR has a special API for this where
the byte string is opened analagous to opening an
array. The encoding of each item in the wrapped
CBOR is encoding on-the-fly:

    QCBOREncode_BstrWrap()
    
QCBOR only supports wrapping using definite lengths
in non-streaming mode. When the string is complete
and close is called, it goes back to write the
head with the length. It can only do this in 
non-streaming mode. When byte-string wrapping,
the length is not known at the start.   


## Streaming, string doesn't fit in the output buffer

In this case the string is in segments and the entire completed string does NOT
fit in the output buffer. This is the full streaming
use case where the string never exists congiguouly in memory. 
It is only contiguous when it is on the wire.

QCBOR supports indefinite lengths for this use case.
The QCBOR encoder must be set up in streaming mode.

    QCBOREncode_OpenIndefiniteLengthBytes()

If the length is known in advance, QCBOR a definite-length
byte string can be output in streaming mode with:

    QCBOREncode_OpenSizedBytes()






How to support streaming and multi-segment definite-length strings

OpenBytes does multi-segment, but is inefficient when the length is known. Not a big deal.

OpenDefLength(size_t uSize)
- writes the QCBOR head
AddChunk( )
- just writes the bytes directly; nothing more

- Could work like OpenBytes and return the UsefulBuf.
- Caller can use AppendDirect(), right?

Close()
- does nothing but internal error checking and book keeping

This will work in streaming mode




## String segements where the final length is known








This discuss QCBOR features to encode and decode large strings and how to hash and encrypt strings without an extra copy.

QCBOR has both a non-streaming and streaming mode for encoding. In the normal, non-streaming mode, the entire encoded output must fit in one buffer. In non-streaming mode, it does not.

QCBOR does not have a streaming mode for decoding. All input must fit in one buffer.



# Non-streaming Encoding

QCBOREncode_AddBytes() is the basic function to encode bytes.
It simply encodes the bytes give to it as a definite-length byte string.

QCBOREncode_OpenIndefiniteLengthBytes(), xx() and yy() encode bytes in chunks as an indefinite-length string.
In non-streaming mode, the output size is still limited by the output buffer size, but the string can be constructed one chunk at a time.
Note that this requires the decoder to handle indefinite-length strings, which generally cannot be assumed.

QCBOREncode_OpenBytes() allows a definite-length string to be output directly to the output buffer without any intermediate buffer as
would be required for QCBOREncode_AddBytes(). It works by returning a UsefulBuf with 
a pointer to the current output position in the output buffer and a length of
the room left in the output buffer. The caller writes directly. This
is particularly useful for outputing encrypted data.

 When QCBOREncode_OpenBytes() is called without giving a length, it internally
 records the position of the CBOR head for the byte string. 
 When QCBOREncode_CloseBytes() is called, it goes back and inserts the length.
 That is, the length doesn't have to be known when encoding starts.
 
  QCBOREncode_OpenBytes() can be called with a length. In that case
  the CBOR head is output right away and there is no going back to insert.
  The exact number of bytes given to QCBOREncode_OpenBytes() must
  have been written or the CBOR produced will be not-well-formed.
  
  Note that QCBOREncode_OpenBytes() by passes some of the pointer safety
  that QCBOR generally provides.
  
  ## Byte-string wrapping
  
  It is common to wrap signed data or messages from other protocols in 
  a byte string. QCBOR facilitates this with QCBOREncode_BstrWrap().
  
  A call to QCBOREncode_BstrWrap() opens a byte string (TODO: should it 
  be renamed) almost the same as QCBOREncode_OpenArray() does. After
  the open, output the CBOR that is to be wrapped with all the normal
  QCBOR encoding calls. When complete, call QCBOREncode_CloseBstrWrap2() (TODO: rename?).
  The close will cause QCBOR to go back and insert the CBOR head for
  the byte string. Internally, QCBOREncode_BstrWrap() work almost
  the same as QCBOREncode_OpenArray().
  
  The wrapped CBOR can be arbitrarily large and complex. Wrapped CBOR
  can be nested. The limits are the QCBOR's limit on nesting depth and 
  the size of the output buffer.
  
  Indefinite-length byte strings to wrap CBOR are not supported (the
  means to output the individual string chunks has some complexity).

# Streaming encoding

Call QCBOREncode_SetStream() to go into straming mode. In this mode,
when the buffer that was given to Init() is full, a flush callback is invoked
to empty it. It is only a temporary buffer, not the place where the
final encoded output is.

When QCBOREncode_AddBytes() is called in streaming mode the bytes
being added don't have to fit in the buffer. The flush function
will be called multiple times. The length of the bytes must
be known.

QCBOREncode_OpenIndefiniteLengthBytes() can be used in streaming
mode when the number of bytes is not known. The individual chunks in the
indefinite length string don't have to fit in the buffer.

QCBOREncode_AddStreamedBytes() is a special function that can
only be used in streaming mode. It does the same as QCBOREncode_AddBytes(),
but is more efficient as it doesn't copy the input into the buffer. It
invokes the flush callback directly.



# Use case break down

If the string to be encoded fits into it's own buffer, it is assumed 
that it will fit into an output buffer

## Length is known

These are all definite-length string use cases, though indefinite-length
can be used here.

### String is in a single buffer

QCBOREncode_AddBytes() This is the simplest and very common case. QCBOREncode_AddBytes() works.
There is no incentive to use indefinite-length strings.
It is assumed that the string will also fit into an output buffer. 
There's no streaming.

Mechanically: output head, output string

QCBOREncode_AddStreamedBytes() may also be used and saves a copy operation
when the encoder is in streaming mode.

Mechanically: Put CBOR head in output buffer; flush buffer; directly flush the string without a copy

### String is not in a buffer

This may because the string is too long for a buffer, or because
we don't want to duplicate the entire string in memory.

#### String fits in a fixed output buffer

This might be used for bulk encryption with AES where the length of the
encrypted output can be calculated from the length of the bytes that
are to be encrypted. There are many other use cases here.

QCBOREncode_OpenBytes() works here, but is less efficient because it goes back for the insert.
 
Mechanically: record head position; output segments; go back and insert head
 
 
TODO: QCBOREncode_OpenBytes() with a length give up front.

Mechanically: output head, output string parts
 
QCBOREncode_OpenIndefiniteLengthBytes() work here, but will produce an indefinite-length string
 which can be undesirable. OpenBytes with length up front would be better.

Mechanically: output head, output all the string parts, output break


#### String does not fit in a fixed output buffer

This is now a streaming use case. The only thing separating this from 
the most general streaming use case is that the length is known up front.
That makes encoding as definite-length possible.

QCBOR does not support this use case.
TODO: support QCBOREncode_OpenBytes() streaming


## Length is unknown

Here the final full length is unknown at the start of string encoding.
The string is always in a series of buffers.

This can be the bulk encryption use case when the size of the
plaintext is unknown or the calculation of the final length is not made.

### Strings fits into a fixed output buffer

QCBOREncode_OpenBytes() works great here to produce a definite-length string.

Mechanically: Record start position, encode segments, go back and insert head with length 
 
QCBOREncode_OpenIndefiniteLengthBytes() work here, but will produce an indefinite-length string
 
Mechanically: encode indef-length head, encode chunks, encode break

QCBOREncode_BstrWrap() is super useful when the string contains CBOR. It avoids a whole extra buffer.

Mechanically: record start position, any call to encode CBOR, go back and insert head with length
 

#### String does not fit in a fixed output buffer

This is the full streaming case. Nothing is known up front, nothing fits in a buffer.

QCBOREncode_OpenIndefiniteLengthBytes() with streaming mode is the only way this is supported.
This always produces indefinite-length strings.

Mechanically: encode indef-length head, encode chunks, encode break; output comes through stream flushes

TODO: some new API and design that allows byte string wrapping with indefinite lengths strings




8 cases, but reduces to 5, because
  - if the length is no known, it is never in a single buffer
  - if it is a single buffer, it also fits in the output buffer

Length known
  1. In a single buffer (assume it fits in output buffer)
  Not in a single buffer
     2. Fits in output buffer
     3. Doesn't fit in output buffer  

Length not known
   4. Fits in output buffer (and is in multiple buffers)
   5. Doesn't fit in output buffer (and is in multiple buffers)
   
   --------------
   
Doesn't fit into output buffer
   3. Length known (and is in multiple buffers)
   5. Length unknown (and is in multiple buffers)

Fits in output buffer
   Length known
      1. In a single buffer
      2. In multiple buffers
   4. Length not known (and is in multiple buffers)
   
   -------
1. In a single buffer (length is known, fits in the output buffer)
   
Not in a single buffer
   Length known
      2. Fits in output buffer -- OpenBytes()
      3. Doesn't fit in output buffer -- Streaming case 5
      
   Length unknown
      4. Fits in output buffer
          4a. Is CBOR
      5. Doesn't fit in output buffer -- the full streaming case, indef length only
