#include <cstdio>
#include <iostream>
#include <string>
#include <utils/ZSLMerkleTree.h>
bool IsLittleEdian(void)
{
	static union
	{
		char c[4];
		unsigned long l;
	} uniData = { { 'l', '?', '?', 'b' } };

	return (char)uniData.l == 'l';
}


int main()
{
    printf("hello from ConsoleApplication1!\n");
    return 0;
}