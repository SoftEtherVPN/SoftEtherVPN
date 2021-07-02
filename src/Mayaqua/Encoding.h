#ifndef ENCODING_H
#define ENCODING_H

#include "MayaType.h"

UINT Base64Decode(void *dst, const void *src, const UINT size);
UINT Base64Encode(void *dst, const void *src, const UINT size);

#endif
