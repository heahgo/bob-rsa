#pragma once

#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

void printBN(char* msg, BIGNUM* a);