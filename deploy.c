// gcc deploy.c -o deploy -lm
// ./deploy -i 1.1.1.0/30 -p 3000
// kill $(lsof -t -i:3003)
// kill -9 pid
// netstat -tulpn
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <math.h>
#include <time.h>

#define MAXIPADDRESSES  16777216
#define UserPassLen     8

#define STATIC      0
#define RANGE       1

#define SINGLEIP      0
#define MULTIPLEIP    1

#define START       0
#define END         1

uint8_t proxy_type=MULTIPLEIP;

struct ipBlockStruct{
    char subnetStr[8];
    char ipStr[20];
    uint8_t subnetDec;
    uint32_t ipDec;
    uint32_t ipEndDec;
    uint32_t count;
    uint8_t type;
    char ipAddresses[MAXIPADDRESSES][20];
    uint16_t portAddresses[MAXIPADDRESSES];
    uint16_t portEnd;
};struct ipBlockStruct ipBlock=(struct ipBlockStruct){0};

void dec2IP (char* ipStr,uint32_t ipDec){
    struct in_addr ip_addr;
    ip_addr.s_addr = htonl(ipDec);
    strcpy(ipStr,inet_ntoa(ip_addr));
}
uint32_t ip2Dec (const char * ip){
    unsigned v = 0;
    int i;
    const char * start;
    start = ip;
    for (i = 0; i < 4; i++) {
        char c;
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return 0;
            }
        }
        if (n >= 256) {
            return 0;
        }
        v *= 256;
        v += n;
    }
    return v;
}
int mystrcpy(char* dest, char* src, char delima){
    int len=strlen(src);
    int n=0;
    while(n<len){
        if(src[n]==delima){
            dest[n]=0;
            return n;
        }
        dest[n]=src[n];
        n++;
    }
    return 0;
}
void print_ipBlock(void){
    uint32_t n=0;
    while(n<ipBlock.count){
        printf("ipAddress:%s:%u\n",ipBlock.ipAddresses[n],ipBlock.portAddresses[n]);
        n++;
    }
}
void process_subnet(char* argv){
    char delima[2]={'/'};
    char *pointer=strstr(argv,delima);
    if(pointer==NULL){
        ipBlock.type=STATIC;
        strcpy(ipBlock.ipStr,argv);
        ipBlock.ipDec=ip2Dec(ipBlock.ipStr);
        dec2IP(ipBlock.ipAddresses[0],(ipBlock.ipDec));
        ipBlock.count=1;
    }
    else{
        ipBlock.type=RANGE;
        strcpy(ipBlock.subnetStr,pointer+1);
        ipBlock.subnetDec=atoi(ipBlock.subnetStr);
        if(ipBlock.subnetDec<8){printf("ERROR:Subnet must be greater than 7\n");exit(1);}
        mystrcpy(ipBlock.ipStr,argv,'/');
        ipBlock.ipDec=ip2Dec(ipBlock.ipStr);
        ipBlock.count=(uint32_t)pow(2,(32-ipBlock.subnetDec));
        uint32_t n=0;
        while(n<ipBlock.count){
            dec2IP(ipBlock.ipAddresses[n],(ipBlock.ipDec+n));
            n++;
        }
    }
}
void process_port(char* argv, uint8_t type){
    uint32_t n=0;
    uint16_t portDec=atoi(argv);
    if(type==START){
        if((65535-portDec)<ipBlock.count){
        printf("ERROR:Port out of range\n");
        exit(1);
        }
        while(n<ipBlock.count){
            ipBlock.portAddresses[n]=portDec+n;
            n++;
        }
    }
    else if(type==END){
        if(portDec<ipBlock.portAddresses[0]){
            printf("ERROR: End port is smaller than Start Port\t");
            exit(1);
        }
        if(portDec-ipBlock.portAddresses[0]>65535){
            printf("ERROR: Port range exceeds 65535\t");
            exit(1);
        }
        ipBlock.portEnd=portDec;
    }
}
void print_usage(void){
    printf("USAGE: ./deploy -i 192.168.0.0/24 -p 3000\n");
}
void parse_options(int argc, char *argv[]) {
    int c;
    uint8_t check=0;
    while ((c = getopt(argc, argv, "i:p:q:")) != -1) {
        switch(c) {
            case 'i':
                process_subnet(optarg);
                check++;
                break;
            case 'p':
                process_port(optarg,START);
                check++;
                break;
            case 'q':
                proxy_type=SINGLEIP;
                process_port(optarg,END);
                check++;
                break;
            default:
                print_usage();
                exit(1);
        }
    }
    if(check<2){
        print_usage();
        exit(1);
    }
}
void remove_last_char(char* line){
    uint8_t len=strlen(line);
    line[len-1]='\0';
}
int getProcessID(char* process){
    char line[1024]={0};
    char query[2048]={0};sprintf(query,"pgrep %s", process);
    FILE *cmd=NULL;cmd=popen(query,"r");
    if(cmd==NULL){
        return 0;
    }
    while(fgets(line, sizeof(line),cmd)!=NULL) {
        remove_last_char(line);
        pclose(cmd);
        return atoi(line);
    }
    pclose(cmd);
    return 0;
}
void dump_proxy(int pid, char* ip, uint16_t port, char* user, char* pass){
    char query[1024]={0};
    sprintf(query,"echo '%s:%u:%s:%s' >> proxy_lists/%u.list",ip,port,user,pass,ipBlock.portAddresses[0]);
    system(query);
    sprintf(query,"echo '%d' >> proxy_pids/%u.list",pid,ipBlock.portAddresses[0]);
    system(query);
    printf("%s:%u:%s:%s\n",ip,port,user,pass);
}
void randomPasswordGeneration(int N,char *password){
    int i = 0;
    int randomizer = 0;
    char LETTER[] = "ABCDEFGHIJKLMNOQPRSTUYWVZX";
    randomizer = rand() % 4;
    for (i = 0; i < N; i++) {
        password[i] = LETTER[rand() % 26];
        randomizer = rand() % 4;
    }
    password[N]=0;
}
void deploy_proxy(void){
    if(proxy_type==MULTIPLEIP){
        uint32_t n=0;
        while(n<ipBlock.count){
            char user[UserPassLen+1]={0};
            char pass[UserPassLen+1]={0};
            randomPasswordGeneration(UserPassLen, user);
            randomPasswordGeneration(UserPassLen, pass);
            char query[1024]={0};
            sprintf(query,"gcc src.c -o proxy_exe/%s -lcurl -lb64", ipBlock.ipAddresses[n]);
            system(query);
            sprintf(query,"./proxy_exe/%s -l %u -b %s -h 127.0.0.1 -p 80 -a %s:%s", ipBlock.ipAddresses[n],ipBlock.portAddresses[n],ipBlock.ipAddresses[n],user,pass);
            // sprintf(query,"./proxy_exe/%s -l %u -h 127.0.0.1 -p 80 -a %s:%s", ipBlock.ipAddresses[n],ipBlock.portAddresses[n],user,pass);
            system(query);
            int pid=getProcessID(ipBlock.ipAddresses[n]);
            if(pid!=0)dump_proxy(pid,ipBlock.ipAddresses[n],ipBlock.portAddresses[n],user,pass);
            n++;
        }
    }
    else if(proxy_type==SINGLEIP){
        uint16_t port=ipBlock.portAddresses[0];
        while(port<=ipBlock.portEnd){
            char user[UserPassLen+1]={0};
            char pass[UserPassLen+1]={0};
            randomPasswordGeneration(UserPassLen, user);
            randomPasswordGeneration(UserPassLen, pass);
            char query[1024]={0};
            sprintf(query,"gcc src.c -o proxy_exe/%u -lcurl -lb64", port);
            system(query);
            sprintf(query,"./proxy_exe/%u -l %u -h 127.0.0.1 -p 80 -a %s:%s", port,port,user,pass);
            system(query);
            char portStr[16]={0};sprintf(portStr,"%d",port);
            int pid=getProcessID(portStr);
            if(pid!=0)dump_proxy(pid,ipBlock.ipAddresses[0],port,user,pass);
            port++;
        }
    }
}
void main(int argc, char *argv[]){
    srand((unsigned int)(time(NULL)));
	parse_options(argc, argv);
    // print_ipBlock();
    deploy_proxy();
}