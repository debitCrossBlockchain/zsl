#include <cstdio>
#include <iostream>
#include <string>
#include <utils/NoteEncryption.h>
#include <utils/ZSLMerkleTree.h>
#include <api/ZslApi.h>
#include <utils/Note.h>
bool IsLittleEdian(void)
{
	static union
	{
		char c[4];
		unsigned long l;
	} uniData = { { 'l', '?', '?', 'b' } };

	return (char)uniData.l == 'l';
}

void TestShielding() {
	NoteEncryption objEncryp;
	ZslApi objZsl;
	std::string proof;
	std::string rho = objEncryp.GetErho();
	objZsl.ZslProveShielding(rho, objEncryp.GetEpk(), 365, proof);
	SproutNote objNote(objEncryp, 365, rho);
	std::string send_nf = objNote.SendNullifier();
	std::string cm = objNote.cm();
	bool result = objZsl.ZslVerifyShielding(proof, send_nf, cm, 365);
	if (!result) {
		cout << "TestShielding fail!" << endl;
	}
	else {
		cout << "TestShielding success!" << endl;
	}
}

void TestUnshielding() {
	ZSLMerkleTree objTree(29);
	for (int64_t i = 0; i < 5; i++){
		cout << "TestUnshielding "<<i<<" test!" << endl;
		NoteEncryption objEncryp;
		ZslApi objZsl;
		std::string proof;
		std::string rho = objEncryp.GetErho();
		SproutNote objNote(objEncryp, 365, rho);
		std::string cm = objNote.cm();
		std::string spend_nf = objNote.SpendNullifier();
		objTree.addCommitment(cm);
		std::vector<std::string> witness = objTree.getWitness(cm);
		std::string root = objTree.root();
		objZsl.ZslProveUnshielding(rho, objEncryp.GetEsk(), 365,i, witness, proof);
		bool result = objZsl.ZslVerifyUnshielding(proof, spend_nf, root, 365);
		if (!result) {
			cout << "TestUnshielding fail!" << endl;
		}
		else {
			cout << "TestUnshielding success!" << endl;
		}
	}
}

void TestTransfer(){

}

int main()
{
	printf("hello from ConsoleApplication1!\n");
	//TestShielding();
	TestUnshielding();
	//TestTransfer();
	int a = 0;
	return 0;
}