//
//  tfm_memory_utils.h
//  AttestToken
//
//  Created by Laurence Lundblade on 4/1/19.
//  Copyright © 2019 Laurence Lundblade. All rights reserved.
//

#ifndef tfm_memory_utils_h
#define tfm_memory_utils_h



static inline void tfm_memcpy(void *dest, const void *src, size_t z)
{
    memcpy(dest, src, z);
}

#endif /* tfm_memory_utils_h */
