#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <ctype.h>

#define MAXSIZE 1542

/*define struct for node*/
struct node{
	int ipAdd[4];
	int port;
	int numNeighbors;	
};

/*define struct for neighbor*/
struct neighbor{
	char fake[20];
	char real[20];
	char neiPort[5];
};

/*define struct for thread_sender parameter*/
struct sender_arg{
	struct node self;
	struct neighbor *nei;
	char *in_file;
	int num;
};

/*define struct for linux header*/
struct linux_header {
	unsigned char pType[2];
	unsigned char addType[2];
	unsigned char addLen[2];
	unsigned char sour_Add[6];
	unsigned char unused[2];
	unsigned char protocol[2];
};

/*define struct for ip header*/
struct ip_header {
	unsigned char ver_len;
	unsigned char field;
	unsigned char tot_len[2];
	unsigned char identity[2];
	unsigned char flags[2];
	unsigned char ttl;
	unsigned char protocol;
	unsigned char check_sum[2];
	unsigned char s_Add[4];
	unsigned char d_Add[4];	
};

/*calculate char(hex) to decimal number*/
int chartodec(char c);

/*compare if two ips are same*/
int cmpip(int* ori, int* tgt);

/*receiver function*/
void *receiver();
/*sender function*/
void *sender(void *par);
/*Global variable*/
struct node self;

int main(int argc, char* argv[]){
	FILE *confp;  //configure file
	pthread_t tid_sender, tid_receiver; //two threads: sender and receiver
	char ipStr[20]; //store ip address
	char ipStr2[20]; //store ip address
	char portStr[5]; //store port
	char numStr[3]; //store number of neighbors
	char *pch; //
		
	int i, j;
	int idx[4];
	int rc;
	
	/*command line must have three arguments*/
	if (argc != 3){
		printf("Please input configure file and binary input file!\n");
		exit(1);
	}
	/*open configure file*/
	confp = fopen(argv[1], "r");
	if (confp == NULL){
		printf("can't open configure file\n");
		exit(1);
	}
	
	/*read info from configure file*/
	fscanf(confp, "%s", ipStr);
	fscanf(confp, "%s", portStr);
	fscanf(confp, "%s", numStr);
	
	/*extract ip info from string*/
	pch = strchr(ipStr, '.');
	i = 0;
	while(pch != NULL){
		idx[i] = (int)(pch - ipStr);
		pch = strchr(pch+1, '.');
		i = i + 1;
	}
	idx[3] = (int)strlen(ipStr);
	for(i = 0; i < 4; i++) {
		if (i == 0)
			j = 0;
		else
			j = idx[i-1]+1;
		self.ipAdd[i] = atoi(&ipStr[j]);
	}

	self.port = atoi(portStr); //get port number
	self.numNeighbors = atoi(numStr); //get number of neighbors
	/*struct array to store neighbors' info*/
	struct neighbor nei[self.numNeighbors];
	/*read neighbors' info*/
	for (int ii = 0; ii < self.numNeighbors; ii++){
		memset(ipStr, 0, 20);
		memset(ipStr2, 0, 20);
		memset(numStr, 0, 3);
		fscanf(confp, "%s", ipStr);
		memcpy(nei[ii].fake, ipStr, strlen(ipStr)+1);
		fscanf(confp, "%s", ipStr2);
		memcpy(nei[ii].real, ipStr2, strlen(ipStr2)+1);
		fscanf(confp, "%s", numStr);
		memcpy(nei[ii].neiPort, numStr, strlen(numStr)+1);
	}
	
	fclose(confp); //close configure file

	/*initialize sender thread parameters*/
	struct sender_arg args;
	args.self = self;
	args.nei = nei;
	args.in_file = argv[2];
	args.num = self.numNeighbors;
	
	/*create thread for receiver function*/
	rc = pthread_create(&tid_receiver, NULL, receiver, NULL);
	if (rc != 0){
		printf("create receiver thread failed\n");
		exit(1);
	}
	/*wait 20s for other host so data will not lost*/
	sleep(20);
	/*create thread for sender function*/
	rc = pthread_create(&tid_sender, NULL, sender, &args);
	if (rc != 0){
		printf("create sender thread failed\n");
		exit(1);
	}
	
	/*exit udp communication when press "Enter"*/
	while(1){
		char key = getchar();
		if(key == '\n')
			break;
	}

	return 0;
}

/*calculate from char to decimal*/
int chartodec(char c){
	int low_c = c & 15;
	int high_c = (c & 240) >> 4;
	int num = high_c * 16 + low_c;
	return num;
}

/*compare if two ips are same*/
int cmpip(int* ori, int* tgt){
	int result = 0;	
	for (int j = 0 ; j < 4; j++){
		if (ori[j] != tgt[j]){
			result = 1;
			break;
		}
	}
	return result;
}

/*Receiver function*/
void* receiver() {	
	/*define variables to packet parse*/
	int sockfd; 
    unsigned char buffer[MAXSIZE]; 
    struct sockaddr_in servaddr, cliaddr; 
	int i, j;
	int ii, jj;
	int ipAdd[4];
	struct linux_header *lhd;
	struct ip_header *ip;
	int low, high;
		
	/*Creating socket file descriptor*/
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){ 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
	
	memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
      
    /*Filling server information */
    servaddr.sin_family    = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(self.port); 
      
    /*Bind the socket with the server address */
    if (bind(sockfd, (const struct sockaddr *)&servaddr,  
        sizeof(servaddr)) < 0) { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
	int len, n;
	while(1){
		/*receive data from sender*/
		n = recvfrom(sockfd, (unsigned char *)buffer, MAXSIZE, MSG_WAITALL, 
		(struct sockaddr *) &cliaddr, &len); 
		/*map received string to structs linux_header, ip_header and icmp_control*/
		lhd = (struct linux_header*)(buffer);
		ip = (struct ip_header*)(buffer + sizeof(struct linux_header));
		
		/*convert string to int*/
		for(i = 0; i < 4; i++)
			ipAdd[i] = chartodec(ip->d_Add[i]);
		/*parse packet if receiver's ip is same with destination ip*/
		if (cmpip(self.ipAdd, ipAdd) == 0) {			
			printf("\n\n");
			/*parse Linux cooked capture*/
			printf("-------- Linux Cooked Capture -------\n");
			low = chartodec(lhd->pType[1]); //Packet type
			if (low == 0) {
				printf("\tPacket type: Unicast to us (0)\n");
			} else if (low == 3){
				printf("\tPacket type: Unicast to another host (3)\n");
			} else if (low == 4){
				printf("\tPacket type: Sent by us (4)\n");
			}
			low = chartodec(lhd->addType[1]);
			high = chartodec(lhd->addLen[1]);
			printf("\tLink-layer address type: %d\n", low); //Link-layer address type
			printf("\tLink-layer address length: %d\n", high); //Link-layer address length
			/*Source address*/
			printf("\tSource : %02x:%02x:%02x:%02x:%02x:%02x (%02x:%02x:%02x:%02x:%02x:%02x)\n", lhd->sour_Add[0], lhd->sour_Add[1], 
			lhd->sour_Add[2], lhd->sour_Add[3], lhd->sour_Add[4], lhd->sour_Add[5], lhd->sour_Add[0], lhd->sour_Add[1], lhd->sour_Add[2],
			lhd->sour_Add[3], lhd->sour_Add[4], lhd->sour_Add[5]);
			printf("\tUnused: %02x%02x\n", lhd->unused[0], lhd->unused[1]); //unused info
			printf("\tProtocol: IPv4(0x%02x%02x)\n", lhd->protocol[0], lhd->protocol[1]); //protocol info
			/*print ip header*/
			printf("\n");
			low = (int)(ip->ver_len);
			int version = (low & 240) >> 4; 	
			int hl = (low & 15) * version;      
			printf("--------IP Header---------------\n");
			printf("\t");
			for (i = 7; 4 <= i; i--) {
				printf("%c", (ip->ver_len & (1 << i)) ? '1' : '0');
			}
			printf(" .... = Version: %d\n", version);
			printf("\t.... ");
			for (i = 3; 0 <= i; i--) {
				printf("%c", (ip->ver_len & (1 << i)) ? '1' : '0');
			}
			printf(" = Header Length: %d bytes (%d)\n", hl, (low & 15));
			/*Differentiated Services Field info*/
			printf("\tDifferentiated Services Field: 0x%02x\n", ip->field);
			printf("\t\t");
			for (i = 7; 4 <= i; i--) {
				printf("%c", (ip->field & (1 << i)) ? '1' : '0');
			}
			printf(" ");
			for (i = 3; 2 <= i; i--) {
				printf("%c", (ip->field & (1 << i)) ? '1' : '0');
			}
			low = (int)(ip->field);
			printf(".. = Differentiated Service Codepoint: Class Selector %d (%d)\n", (low & 240) >> 5, ((low & 240) >> 4)*4);
			printf("\t\t.... ..");
			for (i = 1; 0 <= i; i--) {
				printf("%c", (ip->field & (1 << i)) ? '1' : '0');
			}
			printf(" = Explicit Congestion Notification: Not ECN-Capable Transport (%d)\n", (low&3));
			low = chartodec(ip->tot_len[1]);
			high = chartodec(ip->tot_len[0]);
			printf("\tTotal Length: %d\n", (high * 16 * 16 + low));
			low = chartodec(ip->identity[1]);
			high = chartodec(ip->identity[0]);
			/*Identification info*/
			printf("\tIdentification: 0x%02x%02x (%d)\n", ip->identity[0], ip->identity[1], (high * 16 * 16 + low));
			high = (int)(ip->flags[0]);
			version = (high & 128) >> 7;
			hl = (high & 64) >> 6;
			if (hl == 1){
				printf("\tFlags: 0x%02x%02x, Don't fragment\n", ip->flags[0], ip->flags[1]);
				printf("\t\t%d... .... .... .... = Reserved bit: ", version);
				if (version == 1)
					printf("Set\n");
				else
					printf("Not set\n");
				printf("\t\t.1.. .... .... .... = Don't fragment: Set\n");
			}
			else {
				printf("\tFlags: 0x%02x%02x\n", ip->flags[0], ip->flags[1]);
				printf("\t\t%d... .... .... .... = Reserved bit: ", version);
				if (version == 1)
					printf("Set\n");
				else
					printf("Not set\n");
				printf("\t\t.0.. .... .... .... = Don't fragment: Not set\n");
			}
			version = (high & 32) >> 5;
			printf("\t\t..%d. .... .... .... = More fragments: ", version);
			if (version == 1)
				printf("Set\n");
			else
				printf("Not set\n");
			version = high & 31;
			low = (int)(ip->flags[1]);
			printf("\t\t...");
			for (i = 4; 4 <= i; i--) {
				printf("%c ", (high & (1 << i)) ? '1' : '0');
			}
			for (i = 3; 0 <= i; i--) {
				printf("%c", (high & (1 << i)) ? '1' : '0');
			}
			for (i = 7; 4 <= i; i--) {
				printf("%c", (low & (1 << i)) ? '1' : '0');
			}
			printf(" ");
			for (i = 3; 0 <= i; i--) {
				printf("%c", (low & (1 << i)) ? '1' : '0');
			}
			printf(" = Fragement offset: %d\n", (version * 16 * 16 + low));
			/*Time to live info*/
			printf("\tTime to live: %d\n", chartodec(ip->ttl));
			if (chartodec(ip->protocol) == 1)
				printf("\tProtocol: ICMP(1)\n");
			else if (chartodec(ip->protocol) == 4)
				printf("\tProtocol: IPv4(4)\n");
			else if (chartodec(ip->protocol) == 6)
				printf("\tProtocol: TCP(6)\n");
			else if (chartodec(ip->protocol) == 17)
				printf("\tProtocol: UDP(17)\n");
			else if (chartodec(ip->protocol) == 41)
				printf("\tProtocol: IPv6(41)\n");
			else if (chartodec(ip->protocol) == 50)
				printf("\tProtocol: Encapsulating Security Payload(50)\n");
			/*header checksum */
			printf("\tHeader checksum: 0x%02x%02x\n", ip->check_sum[0], ip->check_sum[1]);
			/*source address*/
			printf("\tSource: %d.%d.%d.%d\n", chartodec(ip->s_Add[0]), chartodec(ip->s_Add[1]), chartodec(ip->s_Add[2]), chartodec(ip->s_Add[3]));
			/*destination address*/
			printf("\tDestination: %d.%d.%d.%d\n", chartodec(ip->d_Add[0]), chartodec(ip->d_Add[1]), chartodec(ip->d_Add[2]), chartodec(ip->d_Add[3]));
			printf("\n");
			printf("\n");
			
			double m = (double)n/16;
			int no_rows = (int)(ceil(m)); 	//calculate number of rows for displaying
			/*display packet info*/
			for (i = 0; i < (no_rows - 1); ++i){ 
				printf("00%d0 ", i);
				for (j = 0; j < 16; ++j){
					printf("%02x ", buffer[i*16 + j]);
					if (j == 7)
						printf("\t");
				}
				for(ii = 0; ii < 16; ++ii){
					if (isprint(buffer[i*16 + ii]))
						printf("%c", buffer[i*16 + ii]);
					else
						printf(".");
					if (ii == 7)
						printf("\t");
				}
				printf("\n");				
			}
			
			/*display the last row's info*/
			printf("00%d0 ", no_rows - 1);
			for (i = (no_rows - 1) * 16; i < n; ++i) {
				printf("%02x ", buffer[i]);
				if (i == (no_rows - 1) * 16 + 7)
					printf("\t");
			}
			int num_space = n%16;
			if (num_space < 8)
				printf("\t");
			for(jj = 0; jj < 3*(16 - num_space)-4; ++jj){
				printf(" ");

			}
			for (i = (no_rows - 1) * 16; i < n; ++i) {
				if (isprint(buffer[i]))
					printf("%c", buffer[i]);
				else
					printf(".");
				
				if (i == (no_rows - 1) * 16 + 7)
					printf("\t");
			}
			printf("\n");
			printf("\n");
			printf("\n");	
		}	
		else { //if destination ip is not this host address, then print info
			printf("receive a frame from source IP: %d.%d.%d.%d, ", chartodec(ip->s_Add[0]), 
			chartodec(ip->s_Add[1]), chartodec(ip->s_Add[2]), chartodec(ip->s_Add[3]));
			printf("and destination IP: %d.%d.%d.%d,", chartodec(ip->d_Add[0]), 
			chartodec(ip->d_Add[1]), chartodec(ip->d_Add[2]), chartodec(ip->d_Add[3]));
			printf("but this host IP is: %d.%d.%d.%d\n\n", self.ipAdd[0], self.ipAdd[1],
			self.ipAdd[2], self.ipAdd[3]);
		}
	}
	
}

/*Sender function*/
void* sender(void* par){
	/*define variables for reading packet*/
	struct sender_arg* args = (struct sender_arg*)par;
	pcap_t *pcap;
	char err[PCAP_ERRBUF_SIZE];
	const unsigned char* packet;
	struct pcap_pkthdr header;
	int sockfd;
    struct sockaddr_in servaddr; 
	char* fname = args->in_file; 
	struct linux_header *lhd;
	struct ip_header *ip;
	int low, high;
	int ipAdd[4];
	
	/*open pcap file*/
	if((pcap = pcap_open_offline(fname, err)) == NULL) {
		printf("Error happens when reading pcap file %s : %s\n", 
		fname, err);
		exit(1);
	}	
	/*reading one packet at a time*/
	for(int i = 0; (packet = pcap_next(pcap, &header)) != NULL; ++i){	
		lhd= (struct linux_header*)(packet);
		low = chartodec(lhd->protocol[1]); 
		high = chartodec(lhd->protocol[0]); 
		/*Send IPV4 packet*/
		if ((low == 0) && (high == 8)){
			ip = (struct ip_header*)(packet + sizeof(struct linux_header));
			for(int j = 0; j < 4; j++)
				ipAdd[j] = chartodec(ip->s_Add[j]);
			/*Send packet that source address is same as self*/
			if (cmpip((args->self).ipAdd, ipAdd) == 0){
				/*Creating socket file descriptor */
				if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
					perror("socket creation failed"); 
					exit(EXIT_FAILURE); 
				} 
				low = 0;
				/*set port with neighbor's info, send packet to neighbors*/
				for(int ii = 0; ii < args->num; ii++) {
					memset(&servaddr, 0, sizeof(servaddr)); 
					/*Filling server information */
					servaddr.sin_family = AF_INET; 
					servaddr.sin_port = htons(atoi((args->nei)[ii].neiPort));
					servaddr.sin_addr.s_addr = INADDR_ANY;
					/*Send one packet to server at a time*/
					sendto(sockfd, (char *)packet, header.len, MSG_CONFIRM, 
					(const struct sockaddr *) &servaddr, sizeof(servaddr));													
				}
			}			
		}
	}
	/*close sock when sending is complete*/
	close(sockfd); 	
}
