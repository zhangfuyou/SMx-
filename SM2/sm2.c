#include"sm2.h"
#include"general.h"
#include"digital_signature.h"
#include"key_exchange.h"
#include"public_key_encryption.h"

/*****************************************
��Ϊ������֤������ǩ������Կ�������ӽ���

ecp->point_byte_length��ʾ��ͬ����ʹ�õĶ�����λ��

DEFINE_SHOW_BIGNUM, 16������ʾ��������ֵ
DEFINE_SHOW_STRING��16������ʾ�������ַ���
******************************************/

int main(void) {

	/*
	//������֤
	printf("************************************������֤��ʼ************************************\n");

	ecc_verify(sm2_param_fp_192, TYPE_GFp, 192);
	ecc_verify(sm2_param_fp_256, TYPE_GFp, 256);

	ecc_verify(sm2_param_f2m_193, TYPE_GFp, 193);
	ecc_verify(sm2_param_f2m_257, TYPE_GFp, 257);
	system("pause");
	printf("\n\n");

	//����ǩ��
	printf("********************************����ǩ��********************************\n");

	digital_sign(sm2_param_fp_256, TYPE_GFp, 256);
	digital_sign(sm2_param_f2m_257, TYPE_GFp, 257);
	system("pause");
	printf("\n\n");

	//��Կ����
	printf("********************************��Կ����********************************\n");

	key_exchange(sm2_param_fp_256, TYPE_GFp, 256);
	key_exchange(sm2_param_f2m_257, TYPE_GF2m, 257);
	system("pause");
	printf("\n\n");

	//�ӽ���
	printf("********************************�ӽ���********************************\n");

	public_key_encryption(sm2_param_fp_192, TYPE_GFp, 192);
	public_key_encryption(sm2_param_fp_256, TYPE_GFp, 256);
	public_key_encryption(sm2_param_f2m_193, TYPE_GF2m, 193);
	public_key_encryption(sm2_param_f2m_257, TYPE_GF2m, 257);
	system("pause");
	printf("\n\n");
	*/

	//�Ƽ�����
	
	printf("************************************������֤��ʼ************************************\n");
	ecc_verify(sm2_param_fp_256, TYPE_GFp, 256);
	printf("************************************������֤����************************************\n");
	system("pause");
	printf("\n\n");
	
	
	printf("************************************����ǩ����ʼ************************************\n");
	digital_sign(sm2_param_fp_256, TYPE_GFp, 256);
	printf("************************************����ǩ������************************************\n");
	system("pause");
	printf("\n\n");
	
	
	printf("************************************��Կ������ʼ************************************\n");
	key_exchange(sm2_param_fp_256, TYPE_GFp, 256);
	printf("************************************��Կ��������************************************\n");
	system("pause");
	printf("\n\n");
	
	printf("************************************�ӡ����ܿ�ʼ************************************\n");
	public_key_encryption
	(sm2_param_fp_256, TYPE_GFp, 256);
	printf("************************************�ӡ����ܽ���************************************\n");
	printf("�������������\n");
	system("pause");


	return 0;
}