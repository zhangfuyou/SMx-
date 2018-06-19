#include"sm2.h"
#include"general.h"
#include"digital_signature.h"
#include"key_exchange.h"
#include"public_key_encryption.h"

/*****************************************
分为曲线验证，数字签名，密钥交换，加解密

ecp->point_byte_length表示不同曲线使用的二进制位数

DEFINE_SHOW_BIGNUM, 16进制显示大整数的值
DEFINE_SHOW_STRING，16进制显示二进制字符串
******************************************/

int main(void) {

	/*
	//曲线验证
	printf("************************************曲线验证开始************************************\n");

	ecc_verify(sm2_param_fp_192, TYPE_GFp, 192);
	ecc_verify(sm2_param_fp_256, TYPE_GFp, 256);

	ecc_verify(sm2_param_f2m_193, TYPE_GFp, 193);
	ecc_verify(sm2_param_f2m_257, TYPE_GFp, 257);
	system("pause");
	printf("\n\n");

	//数字签名
	printf("********************************数字签名********************************\n");

	digital_sign(sm2_param_fp_256, TYPE_GFp, 256);
	digital_sign(sm2_param_f2m_257, TYPE_GFp, 257);
	system("pause");
	printf("\n\n");

	//密钥交换
	printf("********************************密钥交换********************************\n");

	key_exchange(sm2_param_fp_256, TYPE_GFp, 256);
	key_exchange(sm2_param_f2m_257, TYPE_GF2m, 257);
	system("pause");
	printf("\n\n");

	//加解密
	printf("********************************加解密********************************\n");

	public_key_encryption(sm2_param_fp_192, TYPE_GFp, 192);
	public_key_encryption(sm2_param_fp_256, TYPE_GFp, 256);
	public_key_encryption(sm2_param_f2m_193, TYPE_GF2m, 193);
	public_key_encryption(sm2_param_f2m_257, TYPE_GF2m, 257);
	system("pause");
	printf("\n\n");
	*/

	//推荐参数
	
	printf("************************************曲线验证开始************************************\n");
	ecc_verify(sm2_param_fp_256, TYPE_GFp, 256);
	printf("************************************曲线验证结束************************************\n");
	system("pause");
	printf("\n\n");
	
	
	printf("************************************数字签名开始************************************\n");
	digital_sign(sm2_param_fp_256, TYPE_GFp, 256);
	printf("************************************数字签名结束************************************\n");
	system("pause");
	printf("\n\n");
	
	
	printf("************************************密钥交换开始************************************\n");
	key_exchange(sm2_param_fp_256, TYPE_GFp, 256);
	printf("************************************密钥交换结束************************************\n");
	system("pause");
	printf("\n\n");
	
	printf("************************************加、解密开始************************************\n");
	public_key_encryption
	(sm2_param_fp_256, TYPE_GFp, 256);
	printf("************************************加、解密结束************************************\n");
	printf("按任意键结束！\n");
	system("pause");


	return 0;
}