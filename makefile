LDLIBS += -lpcap

all: deauthAttack

deauthAttack: CParam.o Mac.o WirelessPacket.o CDeauthAttack.o main.o CParam.h Mac.h WirelessPacket.h CDeauthAttack.h
	g++ -g CParam.o Mac.o WirelessPacket.o CDeauthAttack.o main.o -o $@ -lncurses ${LDLIBS}  

CParam.o : CParam.h CParam.cpp
	g++ -g -c -o $@ CParam.cpp

Mac.o : Mac.h Mac.cpp 
	g++ -g -c -o $@ Mac.cpp 

WirelessPacket.o : Mac.h WirelessPacket.h WirelessPacket.cpp  
	g++ -g -c -o $@  WirelessPacket.cpp

CDeauthAttack.o : CParam.h Mac.h WirelessPacket.h CDeauthAttack.h CDeauthAttack.cpp 
	g++ -g -c -o $@ CDeauthAttack.cpp 

main.o: CParam.h Mac.h CDeauthAttack.h WirelessPacket.h  main.cpp 
	g++ -g -c -o $@ main.cpp

clean:
	rm -f deauthAttack *.o
