#ifndef SIGNATURE_H
#define SIGNATURE_H

#include"sm2.h"

void digital_sign(char **sm2_param, int type, int point_bit_length);

#endif // !SIGNATURE_H
