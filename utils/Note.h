#ifndef NOTE_H_
#define NOTE_H_
#include <cstdio>
#include <iostream>
#include <utils/NoteEncryption.h>
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
	std::string a_sk_;
	std::string a_pk_;
	std::string rho_;

	SproutNote(NoteEncryption& obj, uint64_t value, std::string rho);
	SproutNote(){}

	virtual ~SproutNote(){}

	std::string cm();
	std::string SendNullifier();
	std::string SpendNullifier();
private:
	void cm(unsigned char* rho, unsigned char* pk, uint64_t value, unsigned char* output);
	void SendNullifier(unsigned char* rho, unsigned char* send_nf);
	void SpendNullifier(unsigned char* rho, unsigned char* sk, unsigned char* spend_nf);
};


#endif