LDLIBS += -lpcap

all: deauthAttack

deauthAttack: Mac.o WirelessPacket.o CDeauthAttack.o main.o  Mac.h WirelessPacket.h CDeauthAttack.h
	g++ -g Mac.o WirelessPacket.o CDeauthAttack.o main.o -o $@ -lncurses ${LDLIBS}  

Mac.o : Mac.h Mac.cpp 
	g++ -g -c -o $@ Mac.cpp 

WirelessPacket.o : Mac.h WirelessPacket.h WirelessPacket.cpp  
	g++ -g -c -o $@  WirelessPacket.cpp

CDeauthAttack.o : Mac.h WirelessPacket.h CDeauthAttack.h CDeauthAttack.cpp 
	g++ -g -c -o $@ CDeauthAttack.cpp 

main.o: Mac.h CDeauthAttack.h WirelessPacket.h  main.cpp 
	g++ -g -c -o $@ main.cpp

clean:
	rm -f deauthAttack *.o
