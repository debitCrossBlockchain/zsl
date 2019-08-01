#include <cstdio>
#include <iostream>
#include <string>
#include <utils/NoteEncryption.h>
#include <utils/ZSLMerkleTree.h>
#include <api/ZslApi.h>
#include <utils/Note.h>
#include <zsl.h>

void TestShielding() {
	NoteEncryption objEncryp;
	ZslApi objZsl;
	std::string proof;
	std::string rho = objEncryp.GetErho();
	objZsl.ZslProveShielding(rho, objEncryp.GetEpk(), 365, proof);
	SendNote objNote(objEncryp, 365, rho);
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
	for (int64_t i = 0; i < 2; i++){
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
	ZSLMerkleTree objTree(29);
	NoteEncryption objEnInput1, objEnInput2, objEnOutput1, objEnOutput2;
	ZslApi objZsl;
	std::string proof;

	std::string InputRho1 = objEnInput1.GetErho();
	std::string InputRho2 = objEnInput2.GetErho();
	std::string OutputRho1 = objEnOutput1.GetErho();
	std::string OutputRho2 = objEnOutput2.GetErho();

	SproutNote objInNote1(objEnInput1, 100, InputRho1);
	std::string cm_input1 = objInNote1.cm();
	std::string spend_nf1 = objInNote1.SpendNullifier();
	objTree.addCommitment(cm_input1);

	SproutNote objInNote2(objEnInput2, 100, InputRho2);
	std::string cm_input2 = objInNote2.cm();
	std::string spend_nf2= objInNote2.SpendNullifier();
	objTree.addCommitment(cm_input2);
	
	std::vector<std::string> witness1 = objTree.getWitness(cm_input1);
	std::vector<std::string> witness2 = objTree.getWitness(cm_input2);
	std::string root = objTree.root();

	objZsl.ZslProveTransfer(proof, InputRho1, objEnInput1.GetEsk(), 100, 0, witness1,
		InputRho2, objEnInput2.GetEsk(), 100, 1, witness2,
		OutputRho1, objEnOutput1.GetEpk(),10, OutputRho2, objEnOutput2.GetEpk(), 190);

	SendNote objNoteOut1(objEnOutput1, 10, OutputRho1);
	SendNote objNoteOut2(objEnOutput2, 190, OutputRho2);

	bool result = objZsl.ZslVerifyTransfer(proof, root, spend_nf1, spend_nf2, objNoteOut1.SendNullifier(),
		objNoteOut2.SendNullifier(), objNoteOut1.cm(), objNoteOut2.cm());
	if (!result) {
		cout << "TestTransfer fail!" << endl;
	}
	else {
		cout << "TestTransfer success!" << endl;
	}
}

int main()
{
	printf("hello from ConsoleApplication1!\n");
	TestShielding();
	TestUnshielding();
	TestTransfer();
	return 0;
}