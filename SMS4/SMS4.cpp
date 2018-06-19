#include<stdio.h>
#include<math.h>

//��������
unsigned int strcat(unsigned int a, unsigned int b, unsigned int c, unsigned int d);
unsigned int transT(unsigned int X);				//�ϳ��û�T
unsigned int transT1(unsigned int X);				//�ϳ��û�T1
int Sbox(int n);									//S��
unsigned int left_rotate(unsigned int X, int n);		//ѭ����������
unsigned int *keyExpension(unsigned int *MK);						//������չ�㷨
int *exange(unsigned int A);						//��8λʮ���������ֽ�Ϊ4����λʮ��������

//����ʵ��
/*
*transT		�ϳ��û�T
*A			32λ�����Ʋ���
*return		ת�����32λ�����ƽ��
*/
unsigned int transT(unsigned int A) {
	int *S;
	S = exange(A);
	unsigned int sr0 = Sbox(*S);
	unsigned int sr1 = Sbox(*(S + 1));
	unsigned int sr2 = Sbox(*(S + 2));
	unsigned int sr3 = Sbox(*(S + 3));

	unsigned int B = strcat(sr0, sr1, sr2, sr3);
	unsigned int C = B ^ (left_rotate(B, 2)) ^ (left_rotate(B, 10)) ^ (left_rotate(B, 18)) ^ (left_rotate(B, 24));

	return C;
}

/*
*transT1		�ϳ��û�T1
*A			32λ�����ƵĲ���
*return		ת�����32λ�����ƽ��
*/
unsigned int transT1(unsigned int A) {
	int *S;
	S = exange(A);
	unsigned int sr0 = Sbox(*S);
	unsigned int sr1 = Sbox(*(S + 1));
	unsigned int sr2 = Sbox(*(S + 2));
	unsigned int sr3 = Sbox(*(S + 3));

	unsigned int B = strcat(sr0, sr1, sr2, sr3);
	unsigned int C = B ^ (left_rotate(B, 13)) ^ (left_rotate(B, 23));

	return C;
}

/*
*SboxT		S��ʵ��
*n			�������
*return		�����
*/
int Sbox(int n) {

	int S[16][16] = {
		0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
		0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
		0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
		0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
		0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
		0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
		0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
		0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
		0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
		0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
		0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
		0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
		0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
		0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
		0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
		0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
	};

	int row = (n & 0xf0) >> 4;
	int col = n & 0x0f;
	int result = S[row][col];
	return result;
}

/*
*left_rotate	ѭ������
*X				��Ҫ��λ��32λ��������
*n				��Ҫ�ƶ���λ��
*return			ѭ����λ���
*/
unsigned int left_rotate(unsigned int X, int n) {
	return (((X) << n) | ((X) >> (32 - n)));
}

/*
*strcat			ƴ�Ӻ���
*a				2λʮ��������
*b				2λʮ��������
*c				2λʮ��������
*d				2λʮ��������
*return			���ؽ�4��2λʮ��������ƴ��λһ��8λʮ��������
*/
unsigned int strcat(unsigned int a, unsigned int b, unsigned int c, unsigned int d) {
	unsigned int returnStr;
	returnStr = ((a << 24)&(0xff000000)) | ((b << 16)&(0x00ff0000)) | ((c << 8)&(0x0000ff00)) | (d&(0x000000ff));
	return returnStr;
}

/*
*exange		S��ʵ��
*A			8λʮ��������
*return		���ذ���4��2λʮ��������������ָ��
*/
int *exange(unsigned int A) {
	static int S[4];
	S[0] = A & 0xff000000;
	S[1] = A & 0x00ff0000;
	S[2] = A & 0x0000ff00;
	S[3] = A & 0x000000ff;
	return S;
}

/*
*keyExpension	��Կ��չ����
* *MK			����������Կ������ָ��
*return			���ذ�������Կ������ָ��
*/
unsigned int *keyExpension(unsigned int *MK) {
	static unsigned int RK[32];
	unsigned int K[36];
	unsigned int FK[4] = { 0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC };	//ϵͳ����

	unsigned int CK[32] = {
		0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
		0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
		0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
		0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
		0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
		0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
		0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
		0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
	};

	//��ʼ��K0,K1,K2,K3
	for (int i = 0; i < 4; i++) {
		K[i] = MK[i] ^ FK[i];
	}

	//��ʼ��RK
	for (int i = 0; i < 32; i++) {
		K[i + 4] = K[i] ^ transT1(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
		RK[i] = K[i + 4];
	}

	return RK;
}

/*
*encrypt	���ܺ���
* *X		�������ĵ�����ָ��
* *rk		��������Կ������ָ��
*return		���ذ������ܽ��������ָ��
*/
unsigned int* encrypt(unsigned int *X, unsigned int *rk) {

	

	static unsigned int Y[4];		//��������
	for (int i = 0; i < 32; i++) {
		X[i + 4] = X[i]^transT(X[i + 1]^X[i + 2] ^ X[i + 3] ^ rk[i]);
	}
	Y[0] = X[35];
	Y[1] = X[34];
	Y[2] = X[33];
	Y[3] = X[32];

	return Y;
}

//9.���ܺ���
/*
*decrypt	���ܺ���
* *y		�������ĵ�����ָ��
* *rk		��������Կ������ָ��
*return		���ذ������ܽ��������ָ��
*/
unsigned int * decrypt(unsigned int *y, unsigned int *rk) {
	
	unsigned int Y[36];
	Y[0] = *y;
	Y[1] = *(y+1);
	Y[2] = *(y + 2);
	Y[3] = *(y + 3);
	
	static unsigned int X[4];		//��������
	for (int i = 0; i < 32; i++) {
		Y[i + 4] = Y[i] ^ transT(Y[i + 1] ^ Y[i + 2] ^ Y[i + 3] ^ rk[31-i]);
	}
	X[0] = Y[35];
	X[1] = Y[34];
	X[2] = Y[33];
	X[3] = Y[32];

	return X;
}

//10.��ӡ���
void print(unsigned int *P) {
	for (int i = 0; i < 4; i++) {
		printf("%08x ", P[i]);
	}
	printf("\n");
}

int main(void) {
	unsigned int MK[4] = { 0x01234567,0x89abcdef,0xfedcba98,0x76543210 };	//������Կ
	unsigned int X[36];														//��Ҫ���ܵ�����
	
	X[0] = 0x01234567;
	X[1] = 0x89abcdef;
	X[2] = 0xfedcba98;
	X[3] = 0x76543210;
	
	unsigned int *rk;
	unsigned int *encrypt_result;
	unsigned int *decrypt_result;
	rk = keyExpension(MK);
	encrypt_result =encrypt(X,rk);
	decrypt_result = decrypt(encrypt_result, rk);

	printf("��Ҫ���ܵ��ֶ�Ϊ��\n");
	print(X);
	
	printf("���ܽ��Ϊ��\n");
	print(encrypt_result);
	
	printf("���ܽ��Ϊ��\n");
	print(decrypt_result);
	
	getchar();
	return 0;
}