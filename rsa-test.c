#include "rsa.h"
#include "utilBN.h"


void PrintUsage()
{
	printf("usage: rsa-test [-k|-e e n plaintext|-d p q dp dq qInv ciphertext]\n");
}

int main(int argc, char* argv[])
{
	RSA* rsa = RSA_new();
	BIGNUM* in = BN_new();
	BIGNUM* out = BN_new();

	if (argc == 2 && !strncmp(argv[1], "-k", 2)) { // keygen option
		RSA_KeyGen(rsa, 1024);

        printf("n : ");
		BN_print_fp(stdout, rsa->n);
		printf("\n");
        printf("e : ");
		BN_print_fp(stdout, rsa->e);
		printf("\n");
        printf("p : ");
		BN_print_fp(stdout, rsa->p);
		printf("\n");
        printf("q : ");
		BN_print_fp(stdout, rsa->q);
		printf("\n");
        printf("dp : ");
		BN_print_fp(stdout, rsa->dp);
		printf("\n");
        printf("dq : ");
		BN_print_fp(stdout, rsa->dq);
        printf("\n");
		printf("qInv : ");
		BN_print_fp(stdout, rsa->qInv);
		printf("\n");
	
	} else if (argc == 5 && !strncmp(argv[1], "-e", 2)) {
			BN_hex2bn(&rsa->e, argv[2]);
			BN_hex2bn(&rsa->n, argv[3]);
			BN_hex2bn(&in, argv[4]);
			RSA_Enc(out, in, rsa);
			BN_print_fp(stdout, out);
		} else if (argc == 8 && !strncmp(argv[1], "-d", 2)) {
			BN_hex2bn(&rsa->p, argv[2]);
			BN_hex2bn(&rsa->q, argv[3]);
			BN_hex2bn(&rsa->dp, argv[4]);
			BN_hex2bn(&rsa->dq, argv[5]);
			BN_hex2bn(&rsa->qInv, argv[6]);
			BN_hex2bn(&in, argv[7]);
			RSA_Dec(out, in, rsa);
			BN_print_fp(stdout, out);
			} else {
				PrintUsage();
				return -1;
				}	

	if (in != NULL) BN_free(in);
	if (out != NULL) BN_free(out);
	if (rsa != NULL) RSA_free(rsa);

	return 0;
}