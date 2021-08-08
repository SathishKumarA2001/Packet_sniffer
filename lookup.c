#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[]){
//	 for(int i=0;i<10;i++){
//	 char *dev = argv[i];
//	 printf("Device: %s\n", dev);	
//	 }

	char *dev,errbuf[PCAP_ERRBUF_SIZE];
	
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		fprintf(stderr,"Could not find any device : %s\n",errbuf);
		return -1;
	}
	printf("Device Found : %s\n",dev);
	return 0;
}

