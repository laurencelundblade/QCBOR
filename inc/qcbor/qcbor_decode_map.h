#if 0
//
//  qcbor_decode_map.h
//  QCBOR
//
//  Created by Laurence Lundblade on 4/6/20.
//  Copyright © 2020 Laurence Lundblade. All rights reserved.
//

#ifndef qcbor_decode_map_h
#define qcbor_decode_map_h


#include "qcbor_decode.h"




/* Next item must be map or this generates an error.
 
 
This puts the decoder in bounded mode which narrows
decoding to the map entered and enables use of
getting items by label.
 
 Nested maps can be decoded like this by entering
 each map in turn.

  Call QCBORDecode_ExitMap() to exit the current map
 decoding level. When all map decoding layers are exited
 then bounded mode is fully exited.
 
 While in bounded mode, GetNext works as usual on the
 map and the standard in-order traversal cursor
 is maintained. Attempts to get items off the end of the
 map will give error XXX (rather going to the next
 item after the map as it would when not in map
 mode).
 
 You can rewind the inorder traversal cursor to the
 beginning of the map with RewindMap().
 
 Exiting leaves the cursor at the
 data item following the last entry in the map.
 
 Entering and Exiting bounded mode consumes the whole
 map and its contents as a GetNext after exiting
 will return the item after the map. */
QCBORError QCBORDecode_EnterMap(QCBORDecodeContext *pCtx);


void QCBORDecode_ExitMap(QCBORDecodeContext *pCtx);

/*
 Indicate if decoding is in map mode more not.
 */
bool QCBORDecode_InMapMode(QCBORDecodeContext *pCtxt);


/*
 Restarts fetching of items in a map to the start of the
 map. This is for GetNext. It has no effect on
 GetByLabel (which always searches from the start).
 */
void QCBORDecode_RewindMap(QCBORDecodeContext *pCtxt);


QCBORError QCBORDecode_EnterArray(QCBORDecodeContext *pCtx);


void QCBORDecode_ExitArray(QCBORDecodeContext *pCtx);

QCBORError QCBORDecode_EnterArrayFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel);


//QCBORError QCBORDecode_EnterMapX(QCBORDecodeContext *pCtx,  MapDecode *pMap);

                     


/*
 Get an item out of a map.
 
 Decoding must be in bounded mode for this to work.
 
 
 
Seek to the beginning of the map.
Consume items looking for the nLabel.
Always go through the whole map and always look for duplicates.
Return the item found, if no errors.

Allow specification of type required.



*/
QCBORError QCBORDecode_GetItemInMap(QCBORDecodeContext *pCtx,
                         int64_t nLabel,
                         uint8_t qcbor_type,
                         QCBORItem *pItem);


QCBORError QCBORDecode_GetItemInMapSZ(QCBORDecodeContext *pCtx,
const char *szLabel,
uint8_t qcbor_type,
QCBORItem *pItem);

/*
 This gets several labeled items out of a map.
 
 pItemArray is an array of items terminated by an item
 with uLabelType QCBOR_TYPE_NONE.
 
 On input the the array of items is the list of labels to fetch
 items for.
 
 On output the array is the data items found. If the label
 wasn't found, uDataType is QCBOR_TYPE_NONE.
 
 This is a CPU-efficient way to decode a bunch of items in a map. It
 is more efficient than scanning each individually because the map
 only needs to be traversed once.
 
 If any duplicate labels are detected, this returns an error.
 
 This will return maps and arrays that are in the map, but
 provides no way to descend into and decode them.
 
 */
QCBORError QCBORDecode_GetItemsInMap(QCBORDecodeContext *pCtx, QCBORItem *pItemList);



QCBORError QCBORDecode_GetIntInMap(QCBORDecodeContext *pCtx, int64_t nLabel, int64_t *pInt);

QCBORError QCBORDecode_GetIntInMapSZ(QCBORDecodeContext *pCtx, const char *szLabel, int64_t *pInt);


void QCBORDecode_GetBstrInMapSZ(QCBORDecodeContext *pCtx, const char *szLabel, UsefulBufC *pBstr);

void QCBORDecode_GetTextInMapSZ(QCBORDecodeContext *pCtx, const char *szLabel, UsefulBufC *pBstr);


/*
  Find a map in a map by integer label and enter it.
 
 This will do duplicate detection on the particular label.
 
 Call QCBORDecode_ExitMap() to return to the mode / level
 from before this was called.
 
 Seek to to the beginning of the map.
 Consume items looking for nLabel
 */
QCBORError QCBORDecode_EnterMapFromMap(QCBORDecodeContext *pCtx, int64_t nLabel);

QCBORError QCBORDecode_EnterMapFromMapSZ(QCBORDecodeContext *pCtx, const char  *szLabel);




/*
 Normally decoding is just in-order traversal. You can get next
 of any type, get next of a particular type including conversions.
 
 If the cursor is at a map and you enter it, then you can use
 methods that Get things by label, either numeric or string.
 
 These methods work only at the particular level in the map.
 To go into a map nested in a map call the special method
 to enter a map by label.
 
 When in a map, the GetNext methods work too, but only
 to the end of the map. You can't traverse off the end of the
 map.
 
 You can rewind to the start of the map and traverse it again
 with the MapRestart method.
 
 The exit map method will leave the traversal cursor at the first itme after
 the map.
 
 
  The beginning of each map must be recorded so the scan can be done
 through the whole map.
 
  A bit per level to indicate in bounded mode for that level so
  it is clear what GetNext at end does and what happens on MapExit
 and where to set the cursor.
 
 
 
 
 
 
 
 
 
 
 
 */





#endif /* qcbor_decode_map_h */
#endif
