// gcc list.c -o list
// ./list -l
// ./list -t 3000.list
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
void show_lists(void){
	system("ls proxy_pids");
}
void terminate_lists(char* name){
	char filename[128]={0};
	sprintf(filename,"proxy_pids/%s",name);
	FILE* fp=fopen(filename,"r");
	if(fp==NULL){
		printf("ERROR: list invalid\n");
		exit(1);
	}
	char line[32]={0};
	char query[256]={0};
	uint16_t count=0;
	while (fgets(line, sizeof(line), fp)) {
		sprintf(query,"kill -9 %s",line);
		system(query);
		count++;
	}
	printf("%s(%u proxies).............TERMINATED\n", name, count); 
	sprintf(query,"rm -rf %s",filename);
	system(query);
	sprintf(query,"rm -rf proxy_lists/%s",name);
	system(query);
	pclose(fp);
}
void print_lists(char* name){
	char filename[128]={0};
	sprintf(filename,"proxy_lists/%s",name);
	FILE* fp=fopen(filename,"r");
	if(fp==NULL){
		printf("ERROR: list invalid\n");
		exit(1);
	}
	char line[32]={0};
	char query[256]={0};
	uint16_t count=0;
	while (fgets(line, sizeof(line), fp)) {
		printf("%s",line);
	}
	pclose(fp);
}
void print_usage(void){
    printf("USAGE:\n./list -l\n./list -t <LISTNAME>\n");
}
void parse_options(int argc, char *argv[]) {
    int c;
    while ((c = getopt(argc, argv, "t:p:l")) != -1) {
        switch(c) {
            case 'l':
            	show_lists();
                break;
            case 'p':
            	print_lists(optarg);
                break;    
            case 't':
            	terminate_lists(optarg);
                break;
            default:
                print_usage();
                exit(1);
                break;
        }
    }
}

void main(int argc, char *argv[]){
	 if(argc<2){
	 	print_usage();
        exit(1);
	 }
	 parse_options(argc, argv);
}