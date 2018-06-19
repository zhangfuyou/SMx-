#ifndef SM2_COMMON_H
#define SM2_COMMON_H

typedef unsigned char BYTE;

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"SM3.h"
#include<openssl/ec.h>


#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

#define HASH_BYTE_LENGTH	32
#define HASH_BIT_LENGTH		256

#define ABORT printf("error: Line : %d function : %s\n",__LINE__,__FUNCTION__);

#define TYPE_GFp	0
#define TYPE_GF2m	1

#define SUCCESS		1
#define FALL		0

#define MAX_POINT_BYTE_LENGTH  64		//曲线上点中X,Y的最大字节长度

#define DEFINE_SHOW_BIGNUM(x) \
	printf(#x":\n"); \
	show_bignum(x, ecp->point_byte_length);\
	printf("\n\n")

#define DEFINE_SHOW_STRING(x, length1) \
	printf(#x":\n"); \
	show_string(x, length1);\
	printf("\n\n")

//int BN_bn2bin(const BIGNUM *a, unsigned char *to); 取a为二进制到to中，返回字符串长度
#define BUFFER_APPEND_BIGNUM(buffer1, pos1, point_byte_length, x) \
	BN_bn2bin(x, &buffer1[pos1 + point_byte_length - BN_num_bytes(x)]); \
	pos1 = pos1 + point_byte_length

#define BUFFER_APPEND_STRING(buffer1, pos1,length1, x) \
	memcpy_s(&buffer1[pos1],1024, x, length1); \
	pos1 = pos1 + length1

typedef struct {
	BYTE buffer[1024];
	int possition;
	BYTE hash[HASH_BYTE_LENGTH];
}sm2_hash;

typedef struct {
	BIGNUM *x;
	BIGNUM *y;
	EC_POINT *ec_point;
}xy_ecpoint;

/*******************************************************************************/
/*								定义椭圆曲线参数信息							*/
/*******************************************************************************/

typedef struct {
	BN_CTX *ctx;
	BIGNUM *p;
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *n;
	xy_ecpoint * G;
	EC_GROUP *group;
	int type;
	int point_bit_length;
	int point_byte_length;

	EC_GROUP *(*EC_GROUP_new_curve)(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);

	int(*EC_POINT_set_affine_coordinates)(const EC_GROUP *group, EC_POINT *p,
		const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);		//设置仿射坐标

	int(*EC_POINT_get_affine_coordinates)(const EC_GROUP *group,
		const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);	//获取仿射坐标
}ec_param;

typedef struct
{
	BIGNUM *d;
	xy_ecpoint *P;
} sm2_ec_key;


#endif // !SM2_COMMON_H

