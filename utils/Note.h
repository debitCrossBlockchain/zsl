#ifndef NOTE_H_
#define NOTE_H_
#include <cstdio>
#include <iostream>
#include <utils/NoteEncryption.h>
class BaseNote{
protected:
	uint64_t value_ = 0;
	std::string a_sk_;
	std::string a_pk_;
	std::string rho_;
public:
	BaseNote() {}
	BaseNote(uint64_t value, NoteEncryption& obj, std::string& rho) : value_(value), a_sk_(obj.GetEsk()), a_pk_(obj.GetEpk()), rho_(rho) {};
	virtual ~BaseNote() {};
	inline uint64_t value() const { return value_; };
	std::string cm();
private:
	void cm(unsigned char* rho, unsigned char* pk, uint64_t value, unsigned char* output);
};

class SproutNote : public BaseNote {
public:
	SproutNote(NoteEncryption& obj, uint64_t value, std::string& rho);
	SproutNote(){}

	virtual ~SproutNote(){}
	std::string SpendNullifier();
private:
	void SpendNullifier(unsigned char* rho, unsigned char* sk, unsigned char* spend_nf);
};

class SendNote : public BaseNote {
public:
	SendNote(NoteEncryption& obj, uint64_t value, std::string& rho);
	SendNote() {}

	virtual ~SendNote() {}
	std::string SendNullifier();
private:
	void SendNullifier(unsigned char* rho, unsigned char* send_nf);
};


#endif