#include "Note.h"
#include "common.h"
std::string SproutNote::cm(){
	unsigned char output[32];
	unsigned char rho[32];
	unsigned char pk[32];
	HexStringToArray(rho_,rho);
	HexStringToArray(a_pk_, pk);
	cm(rho,pk,value_,output);
	return ArrayToHexString(output, 32);
}

void SproutNote::cm(unsigned char* rho, unsigned char* pk, uint64_t value, unsigned char* output){
	CSHA256 hasher;
	hasher.Write(rho, 32);
	hasher.Write(pk, 32);
	auto value_vec = convertIntToVectorLE_(value);
	hasher.Write(&value_vec[0], value_vec.size());
	hasher.Finalize(output);
}