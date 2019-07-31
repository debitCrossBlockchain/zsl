#include <cstdio>
#include <iostream>
#include <string>
#include <utils//NoteEncryption.h>
#include <utils/ZSLMerkleTree.h>
#include <api//ZslApi.h>
#include <utils//Note.h>
bool IsLittleEdian(void)
{
	static union
	{
		char c[4];
		unsigned long l;
	} uniData = { { 'l', '?', '?', 'b' } };

	return (char)uniData.l == 'l';
}

void TestShielding(){
	NoteEncryption objEncryp;
	ZslApi objZsl;
	std::string proof;
	std::string rho = objEncryp.GetErho();
	objZsl.ZslProveShielding(rho, objEncryp.GetEpk(), 365, proof);
	SproutNote objNote(objEncryp,365, rho);
	std::string send_nf = objNote.SendNullifier();
	std::string cm = objNote.cm();
	bool result = objZsl.ZslVerifyShielding(proof, send_nf, cm, 365);
	int a = 0;
}

int main()
{
    printf("hello from ConsoleApplication1!\n");
	TestShielding();
    return 0;
}