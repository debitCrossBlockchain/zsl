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

void ZslApi::Convert(const std::vector<std::string>& witness, unsigned char auth_path[29][32]){
	for (int i = 0; i < witness.size(); i++) {
		unsigned char item[32];
		HexStringToArray(witness[i], item);
		for (int j = 0; j < 32; j++) {
			auth_path[i][j] = item[j];
		}
	}
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
	Convert(witness, auth_path);
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

void ZslApi::ZslProveTransfer(
	std::string& output_proof,
	const std::string& input_rho_1,
	const std::string& input_pk_1,
	uint64_t input_value_1,
	uint64_t input_tree_position_1,
	const std::vector<std::string>& intput_witness_1,
	const std::string& input_rho_2,
	const std::string& input_pk_2,
	uint64_t input_value_2,
	uint64_t input_tree_position_2,
	const std::vector<std::string>& intput_witness_2,
	const std::string& output_rho_1,
	std::string& output_pk_1,
	uint64_t output_value_1,
	const std::string& output_rho_2,
	const std::string& output_pk_2,
	uint64_t output_value_2
){
	unsigned char proof[584];
	unsigned char input_rho_ptr_1[32];
	unsigned char input_pk_ptr_1[32];
	unsigned char input_rho_ptr_2[32];
	unsigned char input_pk_ptr_2[32];
	unsigned char output_rho_ptr_1[32];
	unsigned char output_pk_ptr_1[32];
	unsigned char output_rho_ptr_2[32];
	unsigned char output_pk_ptr_2[32];

	HexStringToArray(input_rho_1, input_rho_ptr_1);
	HexStringToArray(input_pk_1, input_pk_ptr_1);
	HexStringToArray(input_rho_2, input_rho_ptr_2);
	HexStringToArray(input_pk_2, input_pk_ptr_2);
	HexStringToArray(output_rho_1, output_rho_ptr_1);
	HexStringToArray(output_pk_1, output_pk_ptr_1);
	HexStringToArray(output_rho_2, output_rho_ptr_2);
	HexStringToArray(output_pk_2, output_pk_ptr_2);

	unsigned char auth_path_1[29][32];
	Convert(intput_witness_1, auth_path_1);
	unsigned char auth_path_2[29][32];
	Convert(intput_witness_2, auth_path_2);

	zsl_prove_transfer(
		proof, input_rho_ptr_1, input_pk_ptr_1, input_value_1,input_tree_position_1,auth_path_1, 
		input_rho_ptr_2, input_pk_ptr_2, input_value_2, input_tree_position_2, auth_path_2
		,output_rho_ptr_1, output_pk_ptr_1, output_value_1,
		output_rho_ptr_2, output_pk_ptr_2, output_value_2);
	output_proof = ArrayToHexString(proof, 584);
}

bool ZslApi::ZslVerifyTransfer(
	const std::string& proof,
	const std::string& anchor,
	const std::string& spend_nf_1,
	const std::string& spend_nf_2,
	const std::string& send_nf_1,
	const std::string& send_nf_2,
	const std::string& cm_1,
	const std::string& cm_2
){
	unsigned char proof_ptr[584];
	unsigned char anchor_ptr[32];
	unsigned char spend_nf_ptr_1[32];
	unsigned char spend_nf_ptr_2[32];
	unsigned char send_nf_ptr_1[32];
	unsigned char send_nf_ptr_2[32];
	unsigned char cm_ptr_1[32];
	unsigned char cm_ptr_2[32];

	HexStringToArray(proof, proof_ptr);
	HexStringToArray(anchor, anchor_ptr);
	HexStringToArray(spend_nf_1, spend_nf_ptr_1);
	HexStringToArray(spend_nf_2, spend_nf_ptr_2);
	HexStringToArray(send_nf_1, send_nf_ptr_1);
	HexStringToArray(send_nf_2, send_nf_ptr_2);
	HexStringToArray(cm_1, cm_ptr_1);
	HexStringToArray(cm_2, cm_ptr_2);
	return zsl_verify_transfer(proof_ptr,anchor_ptr,spend_nf_ptr_1,spend_nf_ptr_2,send_nf_ptr_1,send_nf_ptr_2,cm_ptr_1,cm_ptr_2);
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