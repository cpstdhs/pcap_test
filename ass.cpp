#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    char buf[10];
    long hx, chksum_orig, chksum=0;
    long pseudo_header=0;
    int tcp_len=0;
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("----------%u bytes captured----------\n", header->caplen);
    //for(int i = 0 ; (i <= header -> caplen) ; i++)
	//printf("%.2x ", packet[i]);
    printf("Destination MAC: %x:%x:%x:%x:%x:%x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("Source MAC: %x:%x:%x:%x:%x:%x\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

    sprintf(buf, "%x%x", packet[24], packet[25]);
    chksum_orig = strtol(buf, NULL, 16);
    for(int i = 14 ; i <= 32 ; i+=2)
    {
	if(i==24) continue; // if idx = chksum
    	sprintf(buf, "%.2x%.2x", packet[i], packet[i+1]);
	hx = strtol(buf, NULL, 16);
	chksum+=hx;
    }
    chksum = (chksum >> 16) + (chksum & 0xffff);
    chksum = (chksum ^ 0xffff);
    if( chksum == chksum_orig)
    {
    	printf("Source IP: %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);
    	printf("Destination IP: %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);
	sprintf(buf, "%.2x%.2x", packet[34], packet[35]);
	hx = strtol(buf, NULL, 16);
	printf("Source Port: %d\n", hx);
	sprintf(buf, "%.2x%.2x", packet[36], packet[37]);
	hx = strtol(buf, NULL, 16);
	printf("Destination Port: %d\n", hx);
    }
    /*
    for(int i=34; i < header -> caplen; i++)
    {
	    tcp_len++;
    }
    sprintf(buf, "%x%x", packet[50], packet[51]);
    chksum_orig = strtol(buf, NULL, 16);
    chksum=0;
    for(int i=26; i <= 32; i+=2)
    {
	    sprintf(buf, "%x%x", packet[i], packet[i+1]);
	    pseudo_header+=strtol(buf, NULL, 16);
    }
    
    pseudo_header+=packet[23]; // Protocol field
    sprintf(buf, "%.2x", tcp_len);
    hx = strtol(buf, NULL, 16);
    pseudo_header+=hx;
    for(int i=34; i< header -> caplen ; i+=2)
    {
	    if(i==50) continue; // if idx == chksum
	    sprintf(buf, "%.2x%.2x", packet[i], packet[i+1]);
	    hx = strtol(buf, NULL, 16);
	    chksum+=hx;
    }
    chksum+=pseudo_header;
    chksum = (chksum >> 16) + (chksum & 0xffff);
    chksum = (chksum ^ 0xffff);
    printf("pseudo_header: %x\n", pseudo_header);
    printf("checksum: %x\n", chksum);
    */
    printf("-------------------------------------\n", header->caplen);
  }

  pcap_close(handle);
  return 0;
}
