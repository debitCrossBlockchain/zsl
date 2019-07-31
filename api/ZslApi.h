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

	void ZslParamgenShielding();
	void ZslParamgenUnshielding();
	void ZslParamgenTransfer();
private:
	void ZslInitialize();
};
#endif
