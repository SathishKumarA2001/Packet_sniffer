#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[]){
//	 for(int i=0;i<10;i++){
//	 char *dev = argv[i];
//	 printf("Device: %s\n", dev);	
//	 }

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
	return 0;
}

