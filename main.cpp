#include "CDeauthAttack.h"
#include <iostream>
#include <string>

// 요구사항 
/***
1.옵션 처리 
	1-1. ap Mac만 명시될 경우 Broadcast로 공격 
	1-2. station Mac이 명시될 경우 Unicast로 공격 
	1.3. -Auth 옵션 입력시 Deauthentiation가 아닌 Authentiation으로 공격

2.각 공격 별 패킷 철 
	1번 목적지 Mac은 Broadcast로 ap Mac은 입력받은 값으로 
	2번 목적지 Mac은 입력받은 값으로 ap Mac은 입력받은 값으로 
	3번 -auth 옵션 입력시 따로 함수 만들기 

***/





int main(int argc, char* argv[]) 
{
	CParam parameter;
	if (!parameter.parse(argc, argv))
		return -1;

	CDeauthAttack CDeauthAttack(parameter);
	CDeauthAttack.deauthAttack();

	return 0;
}
