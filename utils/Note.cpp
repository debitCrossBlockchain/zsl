#include "Note.h"
#include "common.h"
SproutNote::SproutNote(NoteEncryption& obj, uint64_t value, std::string& rho)
	: BaseNote(value, obj, rho){
}
std::string BaseNote::cm(){
	unsigned char output[32];
	unsigned char rho[32];
	unsigned char pk[32];
	HexStringToArray(rho_,rho);
	HexStringToArray(a_pk_, pk);
	cm(rho,pk,value_,output);
	return ArrayToHexString(output, 32);
}

void BaseNote::cm(unsigned char* rho, unsigned char* pk, uint64_t value, unsigned char* output){
	CSHA256 hasher;
	hasher.Write(rho, 32);
	hasher.Write(pk, 32);
	auto value_vec = convertIntToVectorLE_(value);
	hasher.Write(&value_vec[0], value_vec.size());
	hasher.Finalize(output);
}

std::string SproutNote::SpendNullifier(){
	unsigned char e_rho[32];
	unsigned char e_sk[32];
	unsigned char spend_nf[32];
	HexStringToArray(rho_, e_rho);
	HexStringToArray(a_sk_, e_sk);
	SpendNullifier(e_rho,e_sk,spend_nf);
	return ArrayToHexString(spend_nf, 32);
}

void SproutNote::SpendNullifier(unsigned char* rho, unsigned char* sk, unsigned char* spend_nf){
	unsigned char data[65];
	data[0] = 0x01;
	for (int i = 0; i < 32; i++) {
		data[i + 1] = rho[i];
	}
	for (int i = 0; i < 32; i++) {
		data[i + 33] = sk[i];
	}
	sha256(data, 65, spend_nf);
}

SendNote::SendNote(NoteEncryption& obj, uint64_t value, std::string& rho)
	: BaseNote(value,obj,rho){
}

std::string SendNote::SendNullifier() {
	unsigned char e_rho[32];
	unsigned char send_nf[32];
	HexStringToArray(rho_, e_rho);
	SendNullifier(e_rho, send_nf);
	return ArrayToHexString(send_nf, 32);
}

void SendNote::SendNullifier(unsigned char* rho, unsigned char* send_nf) {
	unsigned char data[33];
	data[0] = 0x00;
	for (int i = 0; i < 32; i++) {
		data[i + 1] = rho[i];
	}
	sha256(data, 33, send_nf);
}