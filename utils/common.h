// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_COMMON_H
#define BITCOIN_CRYPTO_COMMON_H

#if defined(HAVE_CONFIG_H)
#include "bitcoin-config.h"
#endif
#include "sha256.h"
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include "sodium.h"
#include <string>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <vector>
#include <stdio.h>
#include <stdexcept>
using namespace std;

#if defined(NDEBUG)
# error "Zcash cannot be compiled without assertions."
#endif

std::vector<unsigned char> static inline convertIntToVectorLE_(const uint64_t val_int){
	std::vector<unsigned char> bytes;

	for (size_t i = 0; i < 8; i++) {
		bytes.push_back(val_int >> (i * 8));
	}

	return bytes;
}

// Convert bytes into boolean vector. (MSB to LSB)
std::vector<bool> static inline convertBytesVectorToVector_(const std::vector<unsigned char>& bytes){
	std::vector<bool> ret;
	ret.resize(bytes.size() * 8);

	unsigned char c;
	for (size_t i = 0; i < bytes.size(); i++) {
		c = bytes.at(i);
		for (size_t j = 0; j < 8; j++) {
			ret.at((i * 8) + j) = (c >> (7 - j)) & 1;
		}
	}

	return ret;
}

// Convert boolean vector (big endian) to integer
uint64_t static inline convertVectorToInt_(const std::vector<bool>& v){
	if (v.size() > 64) {
		throw std::length_error("boolean vector can't be larger than 64 bits");
	}

	uint64_t result = 0;
	for (size_t i = 0; i < v.size(); i++) {
		if (v.at(i)) {
			result |= (uint64_t)1 << ((v.size() - 1) - i);
		}
	}

	return result;
}

std::string static inline BinToHexString(const char* value, int len) {
	std::string result;
	result.resize(len * 2);
	for (size_t i = 0; i < len; i++) {
		uint8_t item = value[i];
		uint8_t high = (item >> 4);
		uint8_t low = (item & 0x0F);
		result[2 * i] = (high >= 0 && high <= 9) ? (high + '0') : (high - 10 + 'a');
		result[2 * i + 1] = (low >= 0 && low <= 9) ? (low + '0') : (low - 10 + 'a');
	}
	return result;
}

void static inline HexStringToArray(const std::string& input, unsigned char* output) {
	unsigned int c;
	for (int i = 0; i < input.size(); i += 2) {
		std::istringstream hex_stream(input.substr(i, 2));
		hex_stream >> std::hex >> c;
		output[i / 2] = c;
	}
}

std::string static inline ArrayToHexString(unsigned char* array, int len) {
	std::string result;
	result.resize(len * 2);
	for (size_t i = 0; i < len; i++) {
		uint8_t item = array[i];
		uint8_t high = (item >> 4);
		uint8_t low = (item & 0x0f);
		result[2 * i] = (high >= 0 && high <= 9) ? (high + '0') : (high - 10 + 'a');
		result[2 * i + 1] = (low >= 0 && low <= 9) ? (low + '0') : (low - 10 + 'a');
	}
	return result;
}

void static inline sha256(unsigned char* input,int64_t length, unsigned char* output) {
	CSHA256 hasher;
	hasher.Write(input, length);
	hasher.FinalizeNoPadding(output);
}

void static inline Sha256Compress(unsigned char* a, unsigned char* b, unsigned char* output) {
	CSHA256 hasher;
	hasher.Write(a, 32);
	hasher.Write(b, 32);
	hasher.FinalizeNoPadding(output);
}

std::string static inline Sha256CompressEx(std::string& left, std::string& right) {
	unsigned char left_output[left.size()/2];
	unsigned char right_output[right.size()/2];
	unsigned char* output;
	HexStringToArray(left, left_output);
	HexStringToArray(right, right_output);
	Sha256Compress(left_output, right_output, output);
	return ArrayToHexString(output, 32);
}


uint16_t static inline ReadLE16(const unsigned char* ptr)
{
    uint16_t x;
    memcpy((char*)&x, ptr, 2);
    return le16toh(x);
}

uint32_t static inline ReadLE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy((char*)&x, ptr, 4);
    return le32toh(x);
}

uint64_t static inline ReadLE64(const unsigned char* ptr)
{
    uint64_t x;
    memcpy((char*)&x, ptr, 8);
    return le64toh(x);
}

void static inline WriteLE16(unsigned char* ptr, uint16_t x)
{
    uint16_t v = htole16(x);
    memcpy(ptr, (char*)&v, 2);
}

void static inline WriteLE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htole32(x);
    memcpy(ptr, (char*)&v, 4);
}

void static inline WriteLE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htole64(x);
    memcpy(ptr, (char*)&v, 8);
}

uint32_t static inline ReadBE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy((char*)&x, ptr, 4);
    return be32toh(x);
}

uint64_t static inline ReadBE64(const unsigned char* ptr)
{
    uint64_t x;
    memcpy((char*)&x, ptr, 8);
    return be64toh(x);
}

void static inline WriteBE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htobe32(x);
    memcpy(ptr, (char*)&v, 4);
}

void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htobe64(x);
    memcpy(ptr, (char*)&v, 8);
}

int inline init_and_check_sodium()
{
    if (sodium_init() == -1) {
        return -1;
    }

    // What follows is a runtime test that ensures the version of libsodium
    // we're linked against checks that signatures are canonical (s < L).
    const unsigned char message[1] = { 0 };

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char sig[crypto_sign_BYTES];

    crypto_sign_keypair(pk, sk);
    crypto_sign_detached(sig, NULL, message, sizeof(message), sk);

    assert(crypto_sign_verify_detached(sig, message, sizeof(message), pk) == 0);

    // Copied from libsodium/crypto_sign/ed25519/ref10/open.c
    static const unsigned char L[32] =
      { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };

    // Add L to S, which starts at sig[32].
    unsigned int s = 0;
    for (size_t i = 0; i < 32; i++) {
        s = sig[32 + i] + L[i] + (s >> 8);
        sig[32 + i] = s & 0xff;
    }

    assert(crypto_sign_verify_detached(sig, message, sizeof(message), pk) != 0);

    return 0;
}

#endif // BITCOIN_CRYPTO_COMMON_H
