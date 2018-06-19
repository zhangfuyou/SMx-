#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>

//��������
#define T_0_15	(0x79cc4519)
#define T_16_63	(0x7a879d8a)

//��ʱ�����ṹ��
typedef struct cf_con {
	uint32_t reg[8];
	uint32_t SS1;
	uint32_t SS2;
	uint32_t TT1;
	uint32_t TT2;
	uint32_t *V;
}cf_context;

//������չ�ֽṹ
typedef struct w_word_def {
	uint32_t *W;
	uint32_t *WW;
}w_word;

//��ʼֵ
uint32_t IV[8] = {
	0x7380166f,0x4914b2b9, 0x172442d7, 0xda8a0600,
	0xa96f30bc,0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

//1.��������
uint32_t FF_0_15(uint32_t X, uint32_t Y, uint32_t Z) {
	return X^Y^Z;
}

uint32_t FF_16_63(uint32_t X, uint32_t Y, uint32_t Z) {
	return (X&Y) | (X&Z) | (Y&Z);
}

uint32_t GG_0_15(uint32_t X, uint32_t Y, uint32_t Z) {
	return X^Y^Z;
}
uint32_t GG_16_63(uint32_t X, uint32_t Y, uint32_t Z) {
	return (X&Y) | (~X&Z);
}

//2.ѭ�����ƺ���
uint32_t left_rotate(uint32_t X, int n) {
	return (((X) << n) | ((X) >> (32 - n)));
}

//3.�û�����
uint32_t P0(uint32_t X) {
	return X ^ left_rotate(X, 9) ^ left_rotate(X, 17);
}

uint32_t P1(uint32_t X) {
	return X ^ left_rotate(X, 15) ^ left_rotate(X, 23);
}

//4.��������㺯��
uint64_t number_zero(uint8_t *m,uint64_t m_len) {
	uint64_t k_pad_zero1;		//������������
	for (int i = 0;; i++) {
		if (((m_len - 440 + 8 * i) % 512) == 0) {
			k_pad_zero1 = 8 * i;
			break;
		}
	}
	return k_pad_zero1;
}

//5.��亯��
uint8_t * m_padding(uint8_t *m, uint64_t m_len, uint64_t k_pad_zero) {
	uint8_t *m1 = (uint8_t *)malloc((k_pad_zero + m_len + 72) / 8);
	if (m1 == NULL) {
		printf("�ڴ����ʧ�ܣ�\n");
		return NULL;
	}
	memcpy_s(m1, (k_pad_zero+m_len+72) / 8, m, m_len / 8);

	//ĩβ����ַ�"1"
	m1[m_len / 8] = 0x80;

	//����м�k��0
	for (int i = 0; i < (k_pad_zero); i += 8) {
		m1[m_len / 8 + 1 + i / 8] = 0x0;
	}

	//�������64λ
	for (int i = 0; i < 8; i++) {
		m1[((m_len + k_pad_zero) / 8) + 1 + i] = ((m_len) >> (56 - 8 * i))&(0x000000ff);	//��1����Ϊ֮ǰ��䡰1����ʱ��û���ֽ�������k_pad_zero��
	}
	return m1;
}

//6.��Ϣ����
uint32_t * m_grouping(uint8_t *m_padding, uint64_t m_len, uint64_t k_pad_zero) {

	//1.���������Ŀ�������������顣���������uint8_t���ͣ�64��Ԫ��Ϊ512����
	//2.��ÿ�������е�4��������uint8_t����ת��Ϊһ��uint32_t����Ԫ�أ���Ϊһ���֡�ÿ��64��Ԫ�أ���ת��Ϊ16����
	//�洢���������BΪ��ά���飬һά��ʾ��ţ���ά��ʾÿ�������16����
	int n = (m_len + k_pad_zero + 72) / 512;
	uint32_t *B = (uint32_t *)malloc(n * 16*sizeof(uint32_t));
	if (B== NULL) {
		printf("�ڴ����ʧ�ܣ�\n");
		return NULL;
	}
	for (int j = 0; j < n; j++) {
		uint32_t result[16];
		for (int i = 0; i < 64; i += 4) {
			uint32_t r0 = (m_padding[j * 64 + i] >> 4);
			uint32_t r1 = (m_padding[j * 64 + i] & 0x0f);

			uint32_t r2 = (m_padding[j * 64 + i + 1] >> 4);
			uint32_t r3 = (m_padding[j * 64 + i + 1] & 0x0f);

			uint32_t r4 = (m_padding[j * 64 + i + 2] >> 4);
			uint32_t r5 = (m_padding[j * 64 + i + 2] & 0x0f);

			uint32_t r6 = (m_padding[j * 64 + i + 3] >> 4);
			uint32_t r7 = (m_padding[j * 64 + i + 3] & 0x0f);

			uint32_t r = (r0 << 28) | (r1 << 24) | (r2 << 20) | (r3 << 16) | (r4 << 12) | (r5 << 8) | (r6 << 4) | r7;

			result[(i + 1) / 4] = r;		//����������Ժϳ��ֽ����
			B[j*16+(i + 1) / 4] = r;
		}
	}
	//����
	printf("���ѹ�������Ϣ\n");
	for (int j = 0; j < n; j++) {
		for (int i = 0; i < 16; i++) {
			printf("%08x ", B[j * 16 + i]);
			if (((i + 1) % 8) == 0) {
				printf("\n");
			}
		}
	}
	printf("\n");

	return B;
}

//7.��Ϣ��չW
uint32_t * m_w_extension(uint64_t m_len, uint64_t k_pad_zero, uint32_t *B) {
	int n = (m_len + k_pad_zero + 72) / 512;
	uint32_t * W = (uint32_t *)malloc(68 * n * sizeof(uint32_t));
	if (W == NULL) {
		printf("�ڴ����ʧ�ܣ�\n");
		return NULL;
	}

	//1.���ÿһ�����飬ʵ����W��WW
	for (int j = 0; j < n; j++) {
		
		for (int i = 0; i < 16; i++) {
			W[j*68+i] = B[j*16 + i];
		}
		for (int i = 16; i < 68; i++) {
			uint32_t r1 = left_rotate(W[j * 68 + i - 3], 15);
			uint32_t r2 = left_rotate(W[j * 68 + i - 13], 7);
			W[j * 68 + i] = P1(W[j * 68 + i - 16] ^ W[j * 68 + i - 9] ^ r1) ^ r2^W[j * 68 + i - 6];
		}
	}

	printf("��չ�����Ϣ\n");
	printf("W_0 W_1 W_2 W_3...W_67\n");
	for (int j = 0; j < n; j++) {
		for (int i = 1; i <= 68; i++) {
			printf("%08x ", W[j*68+i - 1]);
			if ((i % 8) == 0) {
				printf("\n");
			}
		}
		printf("\n");
	}
	printf("\n\n");
	return W;
}

//8.��Ϣ��չWW
uint32_t * m_ww_extension(uint64_t m_len, uint64_t k_pad_zero, uint32_t *W) {
	int n = (m_len + k_pad_zero + 72) / 512;
	uint32_t * WW = (uint32_t *)malloc(64 * sizeof(uint32_t)*n);
	if (WW == NULL) {
		printf("�ڴ����ʧ�ܣ�\n");
		return NULL;
	}

	for (int j = 0; j < n; j++) {
		for (int i = 0; i < 64; i++) {
			WW[j*64+i] = W[j * 68+i] ^ W[j * 68+i + 4];
		}
	}
	printf("��չ�����Ϣ\n");
	printf("WW_0 WW_1 WW_2 WW_3...WW_67\n");
	for (int j = 0; j < n; j++) {
		for (int i = 1; i <= 64; i++) {
			printf("%08x ", WW[j * 64 + i - 1]);
			if ((i % 8) == 0) {
				printf("\n");
			}
		}
		printf("\n");
	}
	printf("\n\n");
	return WW;
}

//9.ѹ������
int fun_CF(uint64_t m_len, uint64_t k_pad_zero, uint32_t * W, uint32_t *WW, uint32_t *hash) {
	int n = (m_len + k_pad_zero + 72) / 512;
	cf_context *ctx = (cf_context *)malloc(sizeof(cf_context));
	if (ctx == NULL) {
		printf("�ڴ����ʧ�ܣ�\n");
		return 0;
	}
	ctx->V = (uint32_t *)malloc(8 * sizeof(uint32_t));
	if (ctx->V == NULL) {
		printf("�ڴ����ʧ�ܣ�\n");
		return 0;
	}

	for (int i = 0; i < 8; i++) {
		ctx->V[i] = IV[i];
		ctx->reg[i] = ctx->V[i];
	}

	printf("    ");
	for (int i = 0; i < 8; i++) {
		printf("%08x ", ctx->reg[i]);
	}
	printf("\n");

	int i;
	for (int j = 0; j < n; j++) {
		
		for (i = 0; i < 16; i++) {
			uint32_t a = left_rotate(ctx->reg[0], 12);
			uint32_t t = left_rotate(T_0_15, i);
			uint32_t r = a + ctx->reg[4] + t;
			ctx->SS1 = left_rotate(r, 7);
			ctx->SS2 = ctx->SS1 ^ a;
			ctx->TT1 = FF_0_15(ctx->reg[0], ctx->reg[1], ctx->reg[2]) + ctx->reg[3] + ctx->SS2 + WW[j*64+i];
			ctx->TT2 = GG_0_15(ctx->reg[4], ctx->reg[5], ctx->reg[6]) + ctx->reg[7] + ctx->SS1 + W[j * 68 + i];
			ctx->reg[3] = ctx->reg[2];
			ctx->reg[2] = left_rotate(ctx->reg[1], 9);
			ctx->reg[1] = ctx->reg[0];
			ctx->reg[0] = ctx->TT1;
			ctx->reg[7] = ctx->reg[6];
			ctx->reg[6] = left_rotate(ctx->reg[5], 19);
			ctx->reg[5] = ctx->reg[4];
			ctx->reg[4] = P0(ctx->TT2);

			printf("%2d  ", i);
			for (int i = 0; i < 8; i++) {
				printf("%08x ", ctx->reg[i]);
			}
			printf("\n");
		}

		for (i = 16; i < 64; i++) {
			uint32_t a = left_rotate(ctx->reg[0], 12);
			uint32_t t = left_rotate(T_16_63, i);
			uint32_t r = a + ctx->reg[4] + t;
			ctx->SS1 = left_rotate(r, 7);
			ctx->SS2 = ctx->SS1 ^ a;
			ctx->TT1 = FF_16_63(ctx->reg[0], ctx->reg[1], ctx->reg[2]) + ctx->reg[3] + ctx->SS2 + WW[j * 64 + i];
			ctx->TT2 = GG_16_63(ctx->reg[4], ctx->reg[5], ctx->reg[6]) + ctx->reg[7] + ctx->SS1 + W[j * 68 + i];
			ctx->reg[3] = ctx->reg[2];
			ctx->reg[2] = left_rotate(ctx->reg[1], 9);
			ctx->reg[1] = ctx->reg[0];
			ctx->reg[0] = ctx->TT1;
			ctx->reg[7] = ctx->reg[6];
			ctx->reg[6] = left_rotate(ctx->reg[5], 19);
			ctx->reg[5] = ctx->reg[4];
			ctx->reg[4] = P0(ctx->TT2);

			printf("%2d  ", i);
			for (int i = 0; i < 8; i++) {
				printf("%08x ", ctx->reg[i]);
			}
			printf("\n");
		}

		for (int k = 0; k < 8; k++) {
			ctx->V[k] = ctx->reg[k]^ ctx->V[k];
			ctx->reg[k] = ctx->V[k];
		}
		printf("\n\n");
	}//forѭ����������ѹ��ѭ��

	//printf("�Ӵ�ֵy= ");
	for (int i = 0; i < 8; i++) {
		//printf("%08x ", ctx->V[i]);
		hash[i] = ctx->V[i];
	}
	printf("\n");

	return 0;
}

void H_256(uint8_t *m,uint64_t m_len,uint32_t *hash) {
	//uint32_t m_len = (sizeof(m) / sizeof(*(m))) * 8-8;
	printf("m_len=%d\n", m_len);
	uint64_t k_pad_zero = number_zero(m, m_len);
	uint8_t * m_padding_result = m_padding(m, m_len, k_pad_zero);
	uint32_t *B = m_grouping(m_padding_result, m_len, k_pad_zero);
	uint32_t *W = m_w_extension(m_len, k_pad_zero, B);
	uint32_t *WW = m_ww_extension(m_len, k_pad_zero, W);
	fun_CF(m_len, k_pad_zero, W, WW,hash);

	free(m_padding_result);
	free(B);
	free(W);
	free(WW);

	printf("\n");
}

int main(void) {
	
	//uint8_t m[] = "abc";
	uint8_t m[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
	uint32_t *hash =(uint32_t *) malloc(sizeof(uint32_t) * 8);

	H_256(m,512,hash);
	for (int i = 0; i < 8; i++) {
		printf("%08x ",hash[i]);
	}

	getchar();
	return 0;
}