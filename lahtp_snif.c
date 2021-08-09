#include<stdio.h>
#include<pcap.h>
#include<errno.h>
#include<time.h>
#include<netinet/if_ether.h>

int main(){
	char *dev = "wlp2s0b1";
	char err[PCAP_ERRBUF_SIZE];
	pcap_t* pack_desc;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct ether_header *eptr;
	int i;
	
	u_char *hard_ptr;
	
	pack_desc = pcap_open_live(dev,BUFSIZ,0,1,err);
	if(pack_desc == NULL){
		printf("pcap_open_live : %s\n",err);
		return -1;
	}
	
	packet = pcap_next(pack_desc,&header);
	if(packet == NULL){
		printf("Cannot capture packet : %s\n",err);
		return -1;
	} else { 
		printf("Recived packet length : %d\n",header.len);
		printf("Recived time : %s\n",ctime((const time_t*) &header.ts));
		printf("Ethernet Header Length : %d\n",ETHER_HDR_LEN);
		
		eptr = (struct ether_header*) packet;
		
		
		if(ntohs(eptr->ether_type) == ETHERTYPE_IP) { //IP Packet
			printf("Ethernet type hex : 0x%x; dec: %d is an IP_Packet\n",ETHERTYPE_IP,ETHERTYPE_IP);
		} else if(ntohs(eptr->ether_type) == ETHERTYPE_ARP) { //ARP Packet
			printf("Ethernet type hex : 0x%x; dec: %d is an IP_Packet\n",ETHERTYPE_ARP,ETHERTYPE_ARP);
		} else {
			printf("Ethernet type hex : 0x%x; dec: %d is not an IP & ARP Packet\n",ntohs(eptr->ether_type),eptr->ether_type);
			return -1;
		}
		
		//Destination MAC Address
		hard_ptr = eptr->ether_dhost;
		i = ETHER_ADDR_LEN;
		printf("Destination Address: ");
		do {
			printf("%s%x",(i == ETHER_ADDR_LEN) ? " ": ":",*hard_ptr++);
		}while(--i>0); 
		printf("\n");
		
		//Source MAC Address
		hard_ptr = eptr->ether_shost;
		i = ETHER_ADDR_LEN;
		printf("Source Address: ");
		do {
			printf("%s%x",(i == ETHER_ADDR_LEN) ? " ": ":",*hard_ptr++);
		}while(--i>0);
		printf("\n"); 
	}
	return 0;
}










