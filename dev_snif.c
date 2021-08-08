#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct in_addr addr;

int main(int argc,char *argv[]){
	 char *dev = "wlp2s0b1";	/* Device to sniff on */
	 pcap_t *handle;		/* Session handle */
	 char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	 handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	 struct bpf_program fp;		/* The compiled filter expression */
	 char filter_exp[] = "port 23";	/* The filter expression */
	 bpf_u_int32 mask;		/* The netmask of our sniffing device */
	 bpf_u_int32 net;		/* The IP of our sniffing device */
	 
	 if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		 fprintf(stderr, "Can't get netmask for device %s\n", dev);
		 net = 0;
		 mask = 0;
	 }
	 if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		 return 2;
	 }
	 if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return 2;
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return 2;
	 }
	 
	 /* Get Ip address and net_mask in Human readable */
	 char *netp; /* dot notation of the network address */
	 addr.s_addr = net;
  	 netp = inet_ntoa(addr);
  	 printf("inet_addr : %s\n",netp);
  	 
  	 char *maskp;/* dot notation of the network mask    */
  	 addr.s_addr = mask;
  	 maskp = inet_ntoa(addr);
  	 printf("Netmask of inet_addr : %s\n",maskp);
	
	 /*print device and packet */
	 printf("Device name : %s\n",dev);
	 printf("Packet captured : %d\n",handle);
	 return 0;
}
