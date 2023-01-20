#include "Mac.h"
#include <iostream>

enum TYPE
{
	DEAUTHENTICATION = 0xC0,
	AUTHENTICATION = 0xB0,
};

struct ST_DEAUTH_FIXED_PARAMETER
{
	
	u_int16_t reasonCode;

};

struct ST_AUTHENTICATION
{
	u_int16_t 	frameControlField;
	u_int16_t 	duration;
	Mac			dstMac;
	Mac			srcMac;
	Mac			bssidMac;
	u_int16_t	fragmentSeqNum;

};

struct ST_IEEE80211_RADIOTAP_HEADER 
{
    u_int8_t        revision;     
    u_int8_t        pad;
    u_int16_t       length;         
    u_int8_t		present[4];  
	u_int8_t		dataRate;
	u_int16_t		txFlags;
};

struct ST_DEAUTH_WIRELESS_PACKET 
{
	ST_IEEE80211_RADIOTAP_HEADER radioTapHeader;
	ST_AUTHENTICATION authentication;
	ST_DEAUTH_FIXED_PARAMETER fixedParameter;

};


struct ST_AUTH_FIXED_PARAMETER
{
	
	u_int16_t authenticationAlgorithm;
	u_int16_t authenticationSeq;
	u_int16_t statusCode;

};


struct ST_AUTH_WIRELESS_PACKET 
{
	ST_IEEE80211_RADIOTAP_HEADER radioTapHeader;
	ST_AUTHENTICATION authentication;
	ST_AUTH_FIXED_PARAMETER fixedParameter;

};




