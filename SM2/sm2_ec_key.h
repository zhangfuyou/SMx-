#ifndef SM2_EC_KEY_H
#define SM2_EC_KEY_H

#include<OPENSSL/ec.h>

#include"ec_param.h"

#include"xy_ecpoint.h"

sm2_ec_key * sm2_ec_key_new(ec_param *ecp);

void sm2_ec_key_free(sm2_ec_key *eck);

int sm2_ec_key_init(sm2_ec_key *eck, char * string_value, ec_param *ecp);



#endif // !SM2_EC_KEY_H

