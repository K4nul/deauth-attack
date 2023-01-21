#include "CParam.h"

void CParam::usage() 
{
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}


bool CParam::parse(int argc, char* argv[])
{
	if (argc < 3) {
		usage();
		return false;
	}

	for(int i =1; i < argc; i++)
		params.push_back(argv[i]);
		

	return true;
}

