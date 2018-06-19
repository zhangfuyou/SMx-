#include"sm2_ec_key.h"

sm2_ec_key * sm2_ec_key_new(ec_param *ecp) {
	sm2_ec_key *eck;
	eck = (sm2_ec_key *)OPENSSL_malloc(sizeof(sm2_ec_key));

	eck->d = BN_new();
	eck->P = xy_ecpoint_new(ecp);

	return eck;
}

void sm2_ec_key_free(sm2_ec_key *eck) {
	if (eck) {
		BN_free(eck->d);
		xy_ecpoint_free(eck->P);
		OPENSSL_free(eck);
		eck = NULL;
	}
}

int sm2_ec_key_init(sm2_ec_key *eck, char * string_value, ec_param *ecp) {

	int ret;
	int len;
	char *temp;

	temp = NULL;
	len = strlen(string_value);

	//如果长度较长，截取前面部分
	if (len > ecp->point_byte_length * 2) {
		len = ecp->point_byte_length * 2;
		temp = (char *)OPENSSL_malloc(len + 2);
		memset(temp, 0, len + 2);	//清空temp
		memcpy_s(temp, len + 2, string_value, len);	//给temp赋值
		BN_hex2bn(&eck->d, temp);
	}
	else {
		BN_hex2bn(&eck->d, string_value);
	}

	ret = xy_ecpoint_mul_bignum(eck->P, ecp->G, eck->d, ecp);

	return ret;
}