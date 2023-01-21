#include "Mac.h"
#include "WirelessPacket.h"
#include <iostream>
#include <fstream>
#include <string> 
#include <vector>
#include <map>
#include <utility>
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <ncurses.h>

enum mode
{
    BROADCASTDEAUTHATTACK,
    UNICASTDEAUTHATTACK,
    AUTHATTACK
    
};


class CParam
{
public:

	std::vector<std::string> params;

    bool parse(int argc, char* argv[]);
    void usage();
};


class CDeauthAttack
{
private:
	
	pcap_t* pcap;	
    int size;
    u_int8_t type;
    std::vector<char *> packets;

    CParam param;
    

public:

	CDeauthAttack(CParam parameter);
	~CDeauthAttack();
    int deauthAttack();

private:

    u_int8_t getType();
    Mac getMac();
    void makeUnicastDeauth();
    void makeBroadcastDeauth();
    void makeAuth();
    void makePacket(u_int8_t attackMode);
    void sendPacket();    

};