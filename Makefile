all : pcap_test

pcap_test: main.o
	g++ -g -o pcap_test ass.o -lpcap

main.o:
	g++ -g -c -o ass.o ass.cpp

clean:
	rm -f pcap_test
	rm -f *.o

