#include "ZSLMerkleTree.h"
#include"sha256.h"
#include "common.h"
#include <algorithm>
ZSLMerkleTree::ZSLMerkleTree(int64_t depth):num_commitments_(0){
	tree_depth_ = depth;
	max_num_elements_ = (1 << depth);;
	_createEmptyRoots(depth);
}

void ZSLMerkleTree::_createEmptyRoots(int64_t depth) {
	std::string root  = "0000000000000000000000000000000000000000000000000000000000000000";
	empty_roots_.push_back(root);
	for (int64_t i = 0; i < depth - 1; i++) {
		root = combine(root, root);
		empty_roots_.push_back(root);
	}
}

std::vector<string> ZSLMerkleTree::getEmptyRoots() {
	return empty_roots_;
}

std::string ZSLMerkleTree::getEmptyRoot(int64_t depth) {
	if (depth < empty_roots_.size()) {
		std::string& empty_root = empty_roots_[depth];
		return empty_root;
	}
}

std::string ZSLMerkleTree::root() {
	return _calcSubtree(0, tree_depth_);
}

std::string ZSLMerkleTree::combine(std::string& left, std::string& right) {
	return Sha256CompressEx(left, right);
}

int64_t ZSLMerkleTree::getLeafIndex(std::string& cm) {
	int64_t map_index = map_commitment_indices_[cm];
	if (map_index > 0);
	return map_index + 1;
}

std::string ZSLMerkleTree::getCommitmentAtLeafIndex(int64_t index) {
	if (index < num_commitments_) {
		int64_t map_index = index + 1;
		return map_commitments_[map_index];
	}
}

void ZSLMerkleTree::addCommitment(std::string& cm) {
	// Only allow a commitment to be added once to the tree
	auto itr = map_commitment_indices_.find(cm);
	if (itr != map_commitment_indices_.end()) {
		return;
	}

	// Is tree full?
	if (num_commitments_ >= max_num_elements_) {
		return;
	}

	// Add new commitment
	int64_t map_index = ++num_commitments_;
	map_commitment_indices_[cm] = map_index;
	map_commitments_[map_index] = cm;
}

bool ZSLMerkleTree::commitmentExists(std::string& cm) {
	auto itr = map_commitment_indices_.find(cm);
	if (itr != map_commitment_indices_.end()) {
		return true;
	}
}

std::string ZSLMerkleTree::_calcSubtree(int64_t index, int64_t item_depth) {
	// Use pre-computed empty tree root if we know other half of tree is empty
	if (num_commitments_ <= leftShift(index, item_depth)) {
		return empty_roots_[item_depth];
	}
	if (item_depth == 0) {
		int64_t mapIndex = index + 1;
		return map_commitments_[mapIndex];
	}
	else {
		std::string left = _calcSubtree(leftShift(index, 1), item_depth - 1);
		std::string right = _calcSubtree(leftShift(index, 1) + 1, item_depth - 1);
		return combine(left, right);
	}
}

std::vector<std::string> ZSLMerkleTree::getWitness(std::string& cm){
	int64_t index = 0;
	std::vector<std::string> uncles;
	auto iter = map_commitment_indices_.find(cm);
	if (iter != map_commitment_indices_.end()) {
		index = iter->second - 1;
	}
	else {
		std::cerr << "Commitment not found" << std::endl;
		return uncles;
	}
	
	int64_t cur_depth = 0;
	int64_t cur_index = index;
	int64_t i = 0;
	while (cur_depth < tree_depth_) {
		uncles.push_back(_calcSubtree(cur_index ^ 1, cur_depth++));
		cur_index = rightShift(cur_index, 1);
	}
}

int64_t ZSLMerkleTree::leftShift(int64_t v, int64_t n) {
	return v* (1 << n);
}

int64_t ZSLMerkleTree::rightShift(int64_t v, int64_t n) {
	return v / (1 << n);
}