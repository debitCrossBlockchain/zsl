#include "NoteEncryption.h"
#include "common.h"
#include <fstream>
#include <sstream>
#include <string>
using namespace std;
template<class T>
T GetRandomness(){
	union {
		T value;
		char cs[sizeof(T)];
	} u;
	std::ifstream rfin("/dev/urandom");
	rfin.read(u.cs, sizeof(u.cs));
	rfin.close();
	return u.value;
}

NoteEncryption::NoteEncryption(){
	unsigned char pk[32];
	unsigned char sk[32];
	GetKeypair(sk,pk);
	esk_ = ArrayToHexString(sk, 32);
	epk_ = ArrayToHexString(pk, 32);
}

void NoteEncryption::GetRandomness(std::string& output, int64_t len){
	char* buf = new char[len];
	std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
	if (urandom) {
		urandom.read(buf, len);
		if (urandom) {
			output = BinToHexString(buf, len);
		}
		urandom.close();
	}
}
void NoteEncryption::GetRandomness(unsigned char* output, int64_t len){
	std::string hex;
	GetRandomness(hex, len);
	HexStringToArray(hex, output);
}

std::string NoteEncryption::GetErho(){
	GetRandomness(erho_, 32);
	return erho_;
}

void NoteEncryption::GetKeypair(unsigned char* priv, unsigned char* pub){
	GetRandomness(priv, 32);
	sha256(priv, 32, pub);
}