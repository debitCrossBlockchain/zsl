#ifndef ZSL_API_H_
#define ZSL_API_H_
#include <string>
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

	void ZslParamgenShielding();

private:
	void ZslInitialize();
};
#endif
