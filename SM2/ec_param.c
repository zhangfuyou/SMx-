#include"xy_ecpoint.h"
#include"ec_param.h"

/*
*初始化椭圆曲线
*PAB确定一条椭圆曲线的三个参数
*y2=x3+ax+b
*p是素数，一般指F(p)中元素的个数
*a,b确定一条椭圆曲线
*n 基点G的阶（一般要求为素数）
*/

ec_param *ec_param_new(void) {
	ec_param *ecp;
	ecp = (ec_param *)OPENSSL_malloc(sizeof(ec_param));

	//申请一个大数上下文环境
	ecp->ctx = BN_CTX_new();
	ecp->a = BN_new();
	ecp->b = BN_new();
	ecp->n = BN_new();
	ecp->p = BN_new();
	return ecp;
}

//释放空间
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
*初始化椭圆曲线的参数
*ec_param *ecp		椭圆曲线参数结构
*char **			要初始化的值
*int type			椭圆曲线的类型
*int point_bit_length 点坐标的长度
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

	//hex转换成bignumber
	//int BN_hex2bn(BIGNUM **a, const char *str);  赋16进制值str到*a中，返回成功与否

	BN_hex2bn(&ecp->p, string_value[0]);
	BN_hex2bn(&ecp->a, string_value[1]);
	BN_hex2bn(&ecp->b, string_value[2]);
	BN_hex2bn(&ecp->n, string_value[5]);

	//密钥参数group，这个群的概念就是定义曲线上离散的点和相对应的操作
	ecp->group = ecp->EC_GROUP_new_curve(ecp->p, ecp->a, ecp->b, ecp->ctx);

	//椭圆曲线参数的基点G
	ecp->G = xy_ecpoint_new(ecp);
	BN_hex2bn(&ecp->G->x, string_value[3]);
	BN_hex2bn(&ecp->G->y, string_value[4]);
	if (!ecp->EC_POINT_set_affine_coordinates(ecp->group, ecp->G->ec_point, ecp->G->x, ecp->G->y, ecp->ctx)) {
		ABORT;
	}

	//椭圆曲线的点的长度
	ecp->point_bit_length = point_bit_length;
	ecp->point_byte_length = (ecp->point_bit_length + 7) / 8;
	return SUCCESS;
}