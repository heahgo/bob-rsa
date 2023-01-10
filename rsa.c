#include "rsa.h"

BIGNUM* XEuclid(BIGNUM* x, BIGNUM* y, const BIGNUM* a, const BIGNUM* b) {
	// a * x + b * y = gcd(a, b)
	// a * x = 1 mod b
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* q = BN_new();
	BIGNUM* s1 = BN_new();
	BIGNUM* t1 = BN_new();
	BIGNUM* r0 = BN_new();
	BIGNUM* r1 = BN_new();
	BIGNUM* tmp = BN_new();
	BN_copy(r0, a);
	BN_copy(r1, b);
	BN_dec2bn(&x, "1");
	BN_dec2bn(&s1, "0");
	BN_dec2bn(&y, "0");
	BN_dec2bn(&t1, "1");

	while (BN_is_zero(r1) != 1) {
		BN_div(q, tmp, r0, r1, ctx);
		BN_copy(r0, r1);
		BN_copy(r1, tmp);

		BN_mul(tmp, s1, q, ctx);
		BN_sub(tmp, x, tmp);
		BN_copy(x, s1);
		BN_copy(s1, tmp);

		BN_mul(tmp, t1, q, ctx);
		BN_sub(tmp, y, tmp);
		BN_copy(y, t1);
		BN_copy(t1, tmp);
	}
	BN_CTX_free(ctx);
	BN_free(q);
	BN_free(s1);
	BN_free(t1);
	BN_free(r1);
	BN_free(tmp);
	return r0;	// gcd(a, b)
}

int ExpMod(BIGNUM* r, const BIGNUM* a, const BIGNUM* e, BIGNUM* m) { //r = a**e mod m
	BN_CTX* ctx = BN_CTX_new();
	int bin_len = BN_num_bits(e);
	BIGNUM* tmp = BN_new();
	BN_copy(r, a);

	if (BN_is_one(e)) {
		BN_mod(r, a, m, ctx);
		return 1;
	}

	for (int i = bin_len - 1; i > 0; i--) {
		BN_mul(tmp, r, r, ctx);
		BN_mod(r, tmp, m, ctx);

		BN_lshift(tmp, e, bin_len - i);
		BN_mask_bits(tmp, bin_len);
		BN_rshift(tmp, tmp, bin_len - 1);

		if (BN_is_one(tmp)) {
			BN_mul(tmp, r, a, ctx);
			BN_mod(r, tmp, m, ctx);
		}
	}

	BN_free(tmp);
	BN_CTX_free(ctx);

	return 1;
}

int nTo2rd(BIGNUM* r, BIGNUM* d, BIGNUM* n) {// n - 1 = 2**r * d
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* e = BN_new();
	BIGNUM* tmp1 = BN_new();
	BIGNUM* tmp2 = BN_new();

	BN_dec2bn(&tmp1, "1");
	BN_copy(d, n);
	BN_sub(d, d, tmp1);
	BN_dec2bn(&r, "0");
	BN_dec2bn(&e, "128");

	while (BN_is_zero(e) != 1) {
		BN_dec2bn(&tmp2, "2");
		BN_exp(tmp1, tmp2, e, ctx);
		BN_mod(tmp2, d, tmp1, ctx);

		if (BN_is_zero(tmp2) == 1) {
			BN_add(r, r, e);
			BN_div(d, NULL, d, tmp1, ctx);
		}
		else {
			BN_dec2bn(&tmp1, "2");
			BN_div(e, NULL, e, tmp1, ctx);
		}
	}
	BN_free(tmp1);
	BN_free(tmp2);
	BN_free(e);
	BN_CTX_free(ctx);
	return 1;
}

int Miller_Labin_Test(BIGNUM* a, BIGNUM* s, BIGNUM* d, BIGNUM* n) {
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* one = BN_new();
	BIGNUM* two = BN_new();
	BIGNUM* n_sub_1 = BN_new();
	BIGNUM* x = BN_new();

	BN_dec2bn(&one, "1");
	BN_dec2bn(&two, "2");
	BN_sub(n_sub_1, n, one);

	ExpMod(x, a, d, n);	// x = a^d mod n
	if (BN_cmp(x, one) == 0 || BN_cmp(x, n_sub_1) == 0) { // x = 1 or x = n - 1
		BN_free(one);
		BN_free(two);
		BN_free(n_sub_1);
		BN_free(x);
		return 1;
	}
	else {
		BIGNUM* i = BN_new();
		for (BN_zero(i); BN_cmp(i, s) == -1; BN_add(i, i, one)) {	// 0 ~~ (s - 1)
			ExpMod(x, x, two, n);	// x = x^2 mod n
			if (BN_cmp(x, n_sub_1) == 0) {	// x = n - 1
				BN_free(one);
				BN_free(two);
				BN_free(n_sub_1);
				BN_free(x);
				BN_free(i);
				return 1;
			}
		}
		BN_free(one);
		BN_free(two);
		BN_free(n_sub_1);
		BN_free(x);
		BN_free(i);
		return 0;
	}
}

int isPrime(BIGNUM* n) {
	BIGNUM* one = BN_new();
	BIGNUM* two = BN_new();
	BIGNUM* n_sub_1 = BN_new();

	BN_dec2bn(&one, "1");
	BN_dec2bn(&two, "2");
	BN_sub(n_sub_1, n, one);

	if (BN_cmp(n, two) == 0) {	// n = 2
		BN_free(one);
		BN_free(two);
		BN_free(n_sub_1);
		return 1;
	}
	if (BN_is_odd(n) == 0 || BN_cmp(n, two) == -1) {	// n mod 2 == 0 or // n < 2
		BN_free(one);
		BN_free(two);
		BN_free(n_sub_1);
		return 0;
	}
	BIGNUM* r = BN_new();
	BIGNUM* d = BN_new();
	BIGNUM* i = BN_new();
	BIGNUM* count = BN_new();
	BIGNUM* a = BN_new();

	nTo2rd(r, d, n);
	BN_dec2bn(&count, "10");
	for (BN_zero(i); BN_cmp(i, count) == -1; BN_add(i, i, one)) {	// 0 ~~ 9
		BN_rand_range(a, n_sub_1);  // 0 <= a < n - 1
		BN_add(a, a, one);  // 1 <= a < n
		if (Miller_Labin_Test(a, r, d, n) == 0) {
			BN_free(one);
			BN_free(two);
			BN_free(n_sub_1);
			BN_free(r);
			BN_free(d);
			BN_free(i);
			BN_free(count);
			BN_free(a);
			return 0;
		}
	}
	BN_free(one);
	BN_free(two);
	BN_free(n_sub_1);
	BN_free(r);
	BN_free(d);
	BN_free(i);
	BN_free(count);
	BN_free(a);
	return 1;
}

BIGNUM* getPrime(BIGNUM* p, int nBits) {
	char bit[10];
	nBits = nBits / 2;
	sprintf(bit, "%d", nBits);
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* p_len = BN_new();
	BIGNUM* bits = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* two = BN_new();

	BN_dec2bn(&one, "1");
	BN_dec2bn(&two, "2");
	BN_dec2bn(&p_len, bit);	

	BN_exp(bits, two, p_len, ctx);	// bits = 2^p_len
	BN_rand_range(p, bits);	// 0 <= p < bits
	BN_add(p, p, bits);	// bits <= p < 2 * bits
	if (BN_is_odd(p) != 1)
		BN_add(p, p, one);	// odd p
	
	while (1) {
		if (isPrime(p) == 1) {
			BN_CTX_free(ctx);
			BN_free(p_len);
			BN_free(bits);
			BN_free(one);
			BN_free(two);
			break;
		} else 
			BN_add(p, p, two);	//next odd	
	}
}

RSA* RSA_new() {
	RSA* rsa = (RSA*)malloc(sizeof(RSA));
	rsa->e = BN_new();
	rsa->n = BN_new();
	rsa->p = BN_new();
	rsa->q = BN_new();
	rsa->dp = BN_new();
	rsa->dq = BN_new();
	rsa->qInv = BN_new();
	return rsa;
}

int RSA_free(RSA* rsa) {
	BN_free(rsa->e);
	BN_free(rsa->n);
	BN_free(rsa->p);
	BN_free(rsa->q);
	BN_free(rsa->dp);
	BN_free(rsa->dq);
	BN_free(rsa->qInv);
	free(rsa);
	return 1;
}

int RSA_KeyGen(RSA* rsa, int nBits) {
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* one = BN_new();
	BIGNUM* d = BN_new();
	BIGNUM* p_sub_1 = BN_new();
	BIGNUM* q_sub_1 = BN_new();
	BIGNUM* pi = BN_new();
	BIGNUM* tmp1 = BN_new();
	BIGNUM* tmp2 = BN_new();

	getPrime(rsa->p, nBits);	// p
	getPrime(rsa->q, nBits);	// q
	BN_mul(rsa->n, rsa->p, rsa->q, ctx);	// n
	BN_dec2bn(&one, "1");	// 1
	BN_sub(p_sub_1, rsa->p, one);	// p -1
	BN_sub(q_sub_1, rsa->q, one);	// q - 1
	
	XEuclid(rsa->qInv, tmp1, rsa->q, rsa->p);
	if (BN_cmp(rsa->qInv, one) == -1)
		BN_add(rsa->qInv, rsa->qInv, rsa->p);	// qInv = q^(-1) mod p

	BN_mul(pi, p_sub_1, q_sub_1, ctx);	// pi = (p - 1)(q - 1)
	BN_dec2bn(&rsa->e, "65537"); // e = 65537
	
	XEuclid(d, tmp1, rsa->e, pi);
	if (BN_cmp(d, one) == -1) 
		BN_add(d, d, pi);	// d

	BN_mod(rsa->dp, d, p_sub_1, ctx);	// dp = d mod (p - 1)
	BN_mod(rsa->dq, d, q_sub_1, ctx);	// dq = d mod (q - 1)
	
	BN_CTX_free(ctx);
	BN_free(one);
	BN_free(pi);
	BN_free(tmp1);
	BN_free(tmp2);
	BN_free(p_sub_1);
	BN_free(q_sub_1);
	BN_free(d);
	return 1;
}

int RSA_Enc(BIGNUM* c, BIGNUM* m, RSA* rsa) {
	ExpMod(c, m, rsa->e, rsa->n);
	return 1;
}

int RSA_Dec(BIGNUM* m, BIGNUM* c, RSA* rsa) {
	//CRT
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *one = BN_new();
	BIGNUM *tmp = BN_new();
	BIGNUM *m1 = BN_new();
	BIGNUM *m2 = BN_new();

	BN_dec2bn(&one, "1");
											// dp = d mod (p - 1), dq = d mod (q - 1)
	ExpMod(m1, c, rsa->dp, rsa->p);	// m1 = c^dp mod p
	ExpMod(m2, c, rsa->dq, rsa->q);	// m2 = c^dq mod q

	BN_sub(tmp, m1, m2);	// tmp = m1 - m2
	BN_mul(tmp, tmp, rsa->q, ctx);	// tmp = (m1 - m2) * q
	BN_mul(tmp, tmp, rsa->qInv, ctx);	// tmp = (m1 - m2) * q * qInv
	BN_add(m, m2, tmp);	// m = m2 + (m1 - m2) * q * qInv

	BN_CTX_free(ctx);
	BN_free(one);
	BN_free(tmp);
	BN_free(m1);
	BN_free(m2);
	return 0;
}


