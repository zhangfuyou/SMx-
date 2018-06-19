#ifndef SM3_H
#define SM3_H

#ifndef DWORD
typedef unsigned int DWORD;
#endif
#ifndef BYTE
typedef unsigned char BYTE;
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void SM3_hash(BYTE *msg, DWORD len1, DWORD *out_hash);

#endif