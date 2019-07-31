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
) {
	unsigned char e_proof[584];
	unsigned char e_send_nf[32];
	unsigned char e_cm[32];
	HexStringToArray(proof, e_proof);
	HexStringToArray(send_nf, e_send_nf);
	HexStringToArray(cm, e_cm);
	return zsl_verify_shielding(e_proof,e_send_nf,e_cm,value);
}

void ZslApi::ZslParamgenShielding(){
	zsl_paramgen_shielding();
}