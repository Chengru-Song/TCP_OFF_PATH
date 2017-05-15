#include "includes.h"
#define BUFFER_SIZE 1024
#define IP_TCP_BUFF_SIZE IP_TCP_HEADER_LEN + BUFFER_SIZE
#define IP_HEADER_LEN sizeof(struct ip)
#define TCP_HEADER_LEN sizeof(struct tcphdr)
#define IP_TCP_HEADER_LEN IP_HEADER_LEN + TCP_HEADER_LEN
#define SYN 0
#define RST 1
struct reVal{
	int packetCount;
	int x;
	int y;
};

struct message{
    char src_ip[32];
    int src_port;
};

struct spoofedStruct{
	char src_ip[32];
	int src_port;
	char dst_ip[32];
	int dst_port;
	char data[32];
	int seq;
	long timeSync;
};
