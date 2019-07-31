#include "ZslApi.h"
#include "zsl.h"
#include <utils/common.h>
ZslApi::ZslApi(){
	ZslInitialize();
}

void ZslApi::ZslInitialize() {
	zsl_initialize();
}

void ZslApi::ZslProveShielding(
	const std::string& rho,
	const std::string& pk,
	uint64_t value,
	std::string& output_proof
){
	unsigned char proof_str[584];
	unsigned char e_rho[32];
	unsigned char e_pk[32];
	HexStringToArray(rho, e_rho);
	HexStringToArray(pk, e_pk);
	zsl_prove_shielding(e_rho, e_pk, value, proof_str);
	output_proof = ArrayToHexString(proof_str, 584);
}

bool ZslApi::ZslVerifyShielding(
	const std::string& proof,
	const std::string& send_nf,
	const std::string& cm,
	uint64_t value
){
	unsigned char e_proof[584];
	unsigned char e_send_nf[32];
	unsigned char e_cm[32];
	HexStringToArray(proof, e_proof);
	HexStringToArray(send_nf, e_send_nf);
	HexStringToArray(cm, e_cm);
	return zsl_verify_shielding(e_proof,e_send_nf,e_cm,value);
}

void ZslApi::ZslProveUnshielding(
	const std::string& rho,
	const std::string& sk,
	uint64_t value,
	uint64_t tree_position,
	const std::vector<std::string>& witness,
	std::string& output_proof
){
	unsigned char proof[584];
	unsigned char e_rho[32];
	unsigned char e_sk[32];
	HexStringToArray(rho, e_rho);
	HexStringToArray(sk, e_sk);

	unsigned char auth_path[29][32];
	for (int i = 0; i < witness.size(); i++){
		unsigned char item[32];
		HexStringToArray(witness[i], item);
		for (int j = 0; j < 32; j++){
			auth_path[i][j] = item[j];
		}
	}
	zsl_prove_unshielding(e_rho, e_sk, value,tree_position,auth_path, proof);
	output_proof = ArrayToHexString(proof,584);
}

bool ZslApi::ZslVerifyUnshielding(
	const std::string& proof,
	const std::string& spend_nf,
	const std::string& rt,
	uint64_t value
){
	unsigned char e_proof[584];
	unsigned char e_spend_nf[32];
	unsigned char e_rt[32];
	HexStringToArray(proof, e_proof);
	HexStringToArray(spend_nf, e_spend_nf);
	HexStringToArray(rt, e_rt);
	return zsl_verify_unshielding(e_proof, e_spend_nf, e_rt, value);
}

void ZslApi::ZslParamgenShielding(){
	zsl_paramgen_shielding();
}

void ZslApi::ZslParamgenUnshielding(){
	zsl_paramgen_unshielding();
}

void ZslApi::ZslParamgenTransfer(){
	zsl_paramgen_transfer();
}