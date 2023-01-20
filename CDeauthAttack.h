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

enum status
{
    SUCCESS,
    FAIL,
    NEXT
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
	
    char * packet;
	pcap_t* pcap;	
    u_int8_t type;
    CParam param;
    

public:

	CDeauthAttack(CParam parameter);
	~CDeauthAttack();
    int deauthAttack();

private:

    u_int8_t getType();
    Mac getDstMac();
    void makeDeauth();
    void makeAuth();
    void makePacket();
    void sendPacket();    

};