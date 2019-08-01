#ifndef ZSL_API_H_
#define ZSL_API_H_
#include <string>
#include <vector>
class ZslApi{
public:
	ZslApi();
	~ZslApi(){}
	void ZslProveShielding(
		const std::string& rho,
		const std::string& pk,
		uint64_t value,
		std::string& output_proof
	);
	bool ZslVerifyShielding(
		const std::string& proof,
		const std::string& send_nf,
		const std::string& cm,
		uint64_t value
	);
	void ZslProveUnshielding(
		const std::string& rho,
		const std::string& sk,
		uint64_t value,
		uint64_t tree_position,
		const std::vector<std::string>& witness,
		std::string& output_proof
	);
	bool ZslVerifyUnshielding(
		const std::string& proof,
		const std::string& spend_nf,
		const std::string& rt,
		uint64_t value
	);

	void ZslProveTransfer(
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
		const std::string& output_pk_1,
		uint64_t output_value_1,
		const std::string& output_rho_2,
		const std::string& output_pk_2,
		uint64_t output_value_2
	);
	bool ZslVerifyTransfer(
		const std::string& proof,
		const std::string& anchor,
		const std::string& spend_nf_1,
		const std::string& spend_nf_2,
		const std::string& send_nf_1,
		const std::string& send_nf_2,
		const std::string& cm_1,
		const std::string& cm_2
	);

	void ZslParamgenShielding();
	void ZslParamgenUnshielding();
	void ZslParamgenTransfer();
private:
	void ZslInitialize();
	void Convert(const std::vector<std::string>& witness, unsigned char auth_path[29][32]);
};
#endif
