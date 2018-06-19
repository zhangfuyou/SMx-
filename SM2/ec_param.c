#include"xy_ecpoint.h"
#include"ec_param.h"

/*
*��ʼ����Բ����
*PABȷ��һ����Բ���ߵ���������
*y2=x3+ax+b
*p��������һ��ָF(p)��Ԫ�صĸ���
*a,bȷ��һ����Բ����
*n ����G�Ľף�һ��Ҫ��Ϊ������
*/

ec_param *ec_param_new(void) {
	ec_param *ecp;
	ecp = (ec_param *)OPENSSL_malloc(sizeof(ec_param));

	//����һ�����������Ļ���
	ecp->ctx = BN_CTX_new();
	ecp->a = BN_new();
	ecp->b = BN_new();
	ecp->n = BN_new();
	ecp->p = BN_new();
	return ecp;
}

//�ͷſռ�
void ec_param_free(ec_param *ecp) {

	BN_free(ecp->a);
	ecp->a = NULL;
	BN_free(ecp->b);
	ecp->b = NULL;
	BN_free(ecp->p);
	ecp->p = NULL;
	BN_free(ecp->n);
	ecp->p = NULL;

	if (ecp->group) {
		EC_GROUP_free(ecp->group);
		ecp->group = NULL;
	}

	if (ecp->G) {
		xy_ecpoint_free(ecp->G);
	}
	BN_CTX_free(ecp->ctx);
	ecp->ctx = NULL;
	OPENSSL_free(ecp);
}

/*
*��ʼ����Բ���ߵĲ���
*ec_param *ecp		��Բ���߲����ṹ
*char **			Ҫ��ʼ����ֵ
*int type			��Բ���ߵ�����
*int point_bit_length ������ĳ���
*/

int ec_param_init(ec_param *ecp, char ** string_value, int type, int point_bit_length) {
	ecp->type = type;
	if (ecp->type == TYPE_GFp) {
		ecp->EC_GROUP_new_curve = EC_GROUP_new_curve_GFp;
		ecp->EC_POINT_set_affine_coordinates = EC_POINT_set_affine_coordinates_GFp;
		ecp->EC_POINT_get_affine_coordinates = EC_POINT_get_affine_coordinates_GFp;
	}
	else if (ecp->type == TYPE_GF2m) {
		ecp->EC_GROUP_new_curve = EC_GROUP_new_curve_GF2m;
		ecp->EC_POINT_set_affine_coordinates = EC_POINT_set_affine_coordinates_GF2m;
		ecp->EC_POINT_get_affine_coordinates = EC_POINT_get_affine_coordinates_GF2m;
	}

	//hexת����bignumber
	//int BN_hex2bn(BIGNUM **a, const char *str);  ��16����ֵstr��*a�У����سɹ����

	BN_hex2bn(&ecp->p, string_value[0]);
	BN_hex2bn(&ecp->a, string_value[1]);
	BN_hex2bn(&ecp->b, string_value[2]);
	BN_hex2bn(&ecp->n, string_value[5]);

	//��Կ����group�����Ⱥ�ĸ�����Ƕ�����������ɢ�ĵ�����Ӧ�Ĳ���
	ecp->group = ecp->EC_GROUP_new_curve(ecp->p, ecp->a, ecp->b, ecp->ctx);

	//��Բ���߲����Ļ���G
	ecp->G = xy_ecpoint_new(ecp);
	BN_hex2bn(&ecp->G->x, string_value[3]);
	BN_hex2bn(&ecp->G->y, string_value[4]);
	if (!ecp->EC_POINT_set_affine_coordinates(ecp->group, ecp->G->ec_point, ecp->G->x, ecp->G->y, ecp->ctx)) {
		ABORT;
	}

	//��Բ���ߵĵ�ĳ���
	ecp->point_bit_length = point_bit_length;
	ecp->point_byte_length = (ecp->point_bit_length + 7) / 8;
	return SUCCESS;
}