#ifndef NOTE_H_
#define NOTE_H_
#include <cstdio>
#include <iostream>
class BaseNote{
protected:
	uint64_t value_ = 0;
public:
	BaseNote() {}
	BaseNote(uint64_t value) : value_(value) {};
	virtual ~BaseNote() {};
	inline uint64_t value() const { return value_; };
};

class SproutNote : public BaseNote {
public:
	std::string a_pk_;
	std::string rho_;

	SproutNote(std::string a_pk, uint64_t value, std::string rho)
		: BaseNote(value), a_pk_(a_pk), rho_(rho){}

	SproutNote(){}

	virtual ~SproutNote(){}

	std::string cm();

	//std::string nullifier(const SproutSpendingKey& a_sk) const;
private:
	void cm(unsigned char* rho, unsigned char* pk, uint64_t value, unsigned char* output);
};


#endif