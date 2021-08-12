#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<errno.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<time.h>
#include<netinet/if_ether.h>

#define ARP_REQUEST 1
#define ARP_RESPONSE 2
typedef struct _arp_hdr arp_hdr;
struct arp_hdr {
   uint16_t htype;   /* Format of hardware address */
   uint16_t ptype;   /* Format of protocol address */
   uint8_t hlen;    /* Length of hardware address */
   uint8_t plen;    /* Length of protocol address */
   uint16_t op;    /* ARP opcode (command) */
   uint8_t sha[6];  /* Sender hardware address */
   uint8_t spa[4];   /* Sender IP address */
   uint8_t tha[6];  /* Target hardware address */
   uint8_t tpa[4];   /* Target IP address */
};

/* // Under production //
void alert_spoof(char *ip,char *mac){
	char cmd[255];
	printf("ARP_SPOOFING DETECTED - IP:%s -MAC:%s",ip,mac);
	sprintf(cmd,"/usr/bin/notify-send -t 5000 \"Possible ARP attacks using IP: %s MAC: %s\"",ip,mac);
	system(cmd);
}
*/

void alert_welcome(){ 
	system("notify-send -t 5000 \"I am listening for ARP Spoofing Attacks\" ");
}

char* HW_address(uint8_t mac[6]){
	char *m = (char*)malloc(20*sizeof(char));
	sprintf(m,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	return m;
}
	
char* Ip_address(uint8_t ip[4]){
	char *m = (char*)malloc(20*sizeof(char));
	sprintf(m,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[4]);
	return m;
}

int arp_sniff(char *device){
	char *dev =  device;           //"wlp2s0b1"
	char err[PCAP_ERRBUF_SIZE];
	pcap_t* pack_desc;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct ether_header *eptr;
	struct arp_hdr *arp_header = NULL;
	int i;
	u_char *hard_ptr;
	char *SHA,*SPA,*THA,*TPA;
	int counter = 0;
	time_t ct,lt;
	long int diff = 0;
	
	pack_desc = pcap_open_live(dev,BUFSIZ,0,1,err);	
	if(pack_desc == NULL){
		printf("%s\n",err);
		interfaces();
		return -1;
	}else{
		printf("Listening on interface %s\n",dev);
	}
	while(1){		
		packet = pcap_next(pack_desc,&header);
		if(packet == NULL){
			printf("Cannot capture packet : %s\n",err);
			return -1;
		} else {	
			eptr = (struct ether_header*) packet;
			if(ntohs(eptr->ether_type) == ETHERTYPE_ARP) { //ARP Packet
				ct = time(NULL);
				diff = ct-lt;
				printf("Diff : %ld Counter : %d\n",diff,counter);
				if(diff > 10){
					counter = 0;
				}
				arp_header = (struct arp_hdr*) (packet+14);
				printf("Recived an ARP packet of length is: %d\n",header.len);
				printf("Recived time : %s\n",ctime((const time_t*) &header.ts));
				printf("Ethernet Header Length : %d\n",ETHER_HDR_LEN);
				printf("Operation_type : %s\n",(ntohs(arp_header->op) == ARP_REQUEST) ? "ARP_REQUEST" : "ARP_RESPONSE");
				SHA = HW_address(arp_header->sha);
				SPA = Ip_address(arp_header->spa);
				THA = HW_address(arp_header->tha);
				TPA = Ip_address(arp_header->tpa);
				printf("Sender MAC : %s\n",SHA);
				printf("Sender IP :%s\n",SPA);
				printf("Target MAC : %s\n",THA);
				printf("Target IP : %s\n",TPA);
				printf("\n--------------------------------------------\n");		
				counter++;
				lt = time(NULL);
				if(counter > 10){
					printf("ARP_SPOOFING DETECTED - IP:%s -MAC:%s",SPA,SHA);
					//alert_spoof(SPA,SHA);
				}	
			}
		}
	}
	return 0;
}


int interfaces(){
	char dev,err[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces, *temp;
	int i=0;
	
	dev = pcap_findalldevs(&interfaces,err);
	if(dev == -1){
		fprintf(stderr,"Could not find any device : %s\n",err);
		return -1;
	}
	for(temp = interfaces;temp;temp=temp->next){
		printf("Device Found :#%d :  %s\n",++i,temp->name);
	}
	printf("If you Enter other than these interfaces, It will sniff empty interface\n");
	return 0;

}

void name(){
	

printf(" _       ___   _   _ ___________\n");                                         
printf("| |     / _ \\ | | | |_   _| ___ \\\n");                                        
printf("| |    / /_\\ \\| |_| | | | | |_//\n");                                   
printf("| |    |  _  ||  _  | | | |  __/  \n");                                      
printf("| |____| | | || | | | | | | | \n");                                      
printf("\\_____/\\_| |_/\\_| |_/ \\_/ \\_| \n");                                            
                                                                         
                                                                         
printf("  ___  ____________      _____ _   _ _________________ _____ _   _ _____  \n");
printf(" / _ \\ | ___ \\ ___ \\    /  ___| \\ | |_   _|  ___|  ___|_   _| \\ | |  __ \\ \n");
printf("/ /_\\ \\| |_/ / |_/ /    \\ `--.|  \\| | | | | |_  | |_    | | |  \\| | |  \\/ \n");
printf("|  _  ||    /|  __/      `--. \\ . ` | | | |  _| |  _|   | | | . ` | | __ \\ \n");
printf("| | | || |\\ \\| |        /\\__/ / |\\  |_| |_| |   | |    _| |_| |\\  | |_\\ \\\n");
printf("\\_| |_/\\_| \\_\\_|        \\____/\\_| \\_/\\___/\\_|   \\_|    \\___/\\_|\\_/\\____/\n");
            

	printf("\n\nThis tool used for sniffing ARP packets for more info 👇\n");

}
void p_help(char *cmd){
	printf("----------------HELP---------------\n");
	printf("for view interfaces use flag -i\n");
	printf("for help use flag -h\n");
	printf("for name and purpose of tool -n\n");
	printf("----------------------------------\n");
	printf(" Usage: %s -i,-h,-n,-a \n",cmd);
	printf("For sniffing, you should type the interface name like this lahtp_arp_tool -a <interface_name>\n");
	exit(1);
}

int main(int argc,int *argv[]){
	if(access("/usr/bin/notify-send",1) == -1){
		printf("Missing low level dependencies : libnotify-bin\n");
		printf("Install Package : apt-get install libnotify-bin\n");
		name();
		exit(-1);
	}else{
		//alert_spoof(ip,mac); // pending code
		alert_welcome();
		printf("All Dependencies are available\n");
	}
	char *args = argv[0]; //convert int* to char* arguments...
	char *arg = argv[1]; //convert int* to char* arguments...
	char *a = argv[2];   //convert int* to char* arguments...
	if(argc < 4 && argc > 1){
		if(strcmp("-i",arg) == 0){
			interfaces();
		}else if(strcmp("-n",arg) == 0){
			name();
		}else if(strcmp("-h",arg) == 0){
			name();
			p_help(args);
		}else if(strcmp("-a",arg) == 0){
			if(a != NULL){
				arp_sniff(a);
			}else{
				printf("Error: Enter the interface you want to sniff:\n");
				interfaces();
			}
		}
		else {
			printf("** Error: Give any flags among these : -h,-i,-n ** \n");
			p_help(args);
		}
	}else {
		printf("** Error: please give arguments less than 1 more than 0 **\n");
		p_help(args);
	}
}










