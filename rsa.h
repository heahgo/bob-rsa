#pragma once

#include <openssl/bn.h>

typedef struct rsa_st {
	BIGNUM* e;
	BIGNUM* n;
	BIGNUM* p;
	BIGNUM* q;
	BIGNUM* dp;	
	BIGNUM* dq;
	BIGNUM* qInv;
} RSA;

BIGNUM* XEuclid(BIGNUM* x, BIGNUM* y, const BIGNUM* a, const BIGNUM* b);
int ExpMod(BIGNUM* r, const BIGNUM* a, const BIGNUM* e, BIGNUM* m);
int nTo2rd(BIGNUM* r, BIGNUM* d, BIGNUM* n);
int Miller_Labin_Test(BIGNUM* a, BIGNUM* s, BIGNUM* d, BIGNUM* n);
int isPrime(BIGNUM* n);
BIGNUM* getPrime(BIGNUM* p, int nBits);
RSA* RSA_new();
int RSA_free(RSA* rsa);
int RSA_KeyGen(RSA* rsa, int nBits);
int RSA_Enc(BIGNUM* c, BIGNUM* m, RSA* rsa);
int RSA_Dec(BIGNUM* m, BIGNUM* c, RSA* rsa);