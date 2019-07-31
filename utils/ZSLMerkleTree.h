#ifndef ZSL_MERKEL_TREE_H_
#define ZSL_MERKEL_TREE_H_
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>
#include <map>
using namespace std;
class ZSLMerkleTree
{
public:
	ZSLMerkleTree(int16_t depth);
	~ZSLMerkleTree() {}
	std::vector<string> getEmptyRoots();
	std::string getEmptyRoot(int64_t depth);
	std::string combine(std::string& left, std::string& right);
	int64_t getLeafIndex(std::string& cm);
	std::string getCommitmentAtLeafIndex(int64_t index);
	void addCommitment(std::string& cm);
	bool commitmentExists(std::string& cm);
	std::string root();
	std::string _calcSubtree(int64_t index, int64_t item_depth);
	std::vector<std::string> getWitness(std::string& cm);
	int64_t leftShift(int64_t v, int64_t n);
	int64_t rightShift(int64_t v, int64_t n);

private:
	void _createEmptyRoots(int64_t depth);


private:
	int64_t tree_depth_;
	int64_t max_num_elements_;
	std::vector<string> empty_roots_;
	int64_t num_commitments_;
	std::map<string, int64_t> map_commitment_indices_;
	std::map<int64_t, string> map_commitments_;

};
#endif

