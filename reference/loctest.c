/*
 * Oracle built from arpi's nanolibloc.c (reference implementation).
 * Usage: ./loctest <database.db> <ip> [ip ...]
 * Prints country code, flags-unaware ASN per the reference algorithm,
 * used to cross-check the nginx waf_geo.c port against known IPs.
 *
 * Extended over the original: also dumps the raw 12-byte ND leaf so we
 * can read the flags field (offset 2, uint16 BE) that nanolibloc ignores.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define DB_AS 0
#define DB_ND 1
#define DB_NT 2
#define DB_CO 3
#define DB_PO 4

static unsigned char* locdb_data[5];
static unsigned int locdb_len[5];
static unsigned int ipv4root=0;

static inline unsigned int getint(unsigned char* p){
    return (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
}

int locdb_open(char* fn){
    unsigned char magic[8];
    unsigned char header[64];
    FILE* f=fopen(fn,"r");
    if(!f) return 0;
    if(fread(magic,sizeof(magic),1,f)<1) return 0;
    if(getint(magic)!=0x4C4F4344 || getint(magic+4)!=0x42585801) return 0;
    if(fread(header,sizeof(header),1,f)<1) return 0;
    int i;
    for(i=0;i<5;i++){
        unsigned int off=getint(header+20+i*8);
        unsigned int len=getint(header+24+i*8);
        fseek(f,off,SEEK_SET);
        locdb_data[i]=malloc(len);
        if(!locdb_data[i]) return 0;
        if(len!=fread(locdb_data[i],1,len,f)) return 0;
        locdb_len[i]=len;
    }
    unsigned int nxt=0;
    for(i=0;i<96;i++){
        if(nxt*12>=locdb_len[DB_NT]) return 0;
        nxt=getint(locdb_data[DB_NT]+12*nxt+(i<80?0:4));
    }
    ipv4root=nxt;
    return 1;
}

int locdb_lookup6(unsigned char* address,int addrlen,unsigned int nxt){
    int ret=-1,mask=0;
    do{ nxt*=12;
        if(nxt>=locdb_len[DB_NT]) return -1;
        unsigned int net=getint(locdb_data[DB_NT]+nxt+8);
        if(!(net&0x80000000)) ret=net;
        if(mask>>3>=addrlen) break;
        int bit=(address[mask>>3]>>(7-(mask&7)))&1;
        mask++;
        nxt=getint(locdb_data[DB_NT]+nxt+bit*4);
    }while(nxt);
    return ret;
}

int locdb_lookup4(unsigned char* ap){
    unsigned int address=(ap[0]<<24)|(ap[1]<<16)|(ap[2]<<8)|ap[3];
    int ret=-1; unsigned int nxt=ipv4root;
    for(int mask=0;mask<=32;mask++){
        nxt*=12;
        if(nxt>=locdb_len[DB_NT]) return -1;
        unsigned int net=getint(locdb_data[DB_NT]+nxt+8);
        if(!(net&0x80000000)) ret=net;
        int bit=(address>>29)&4;
        nxt=getint(locdb_data[DB_NT]+nxt+bit);
        if(!nxt) break;
        address<<=1;
    }
    return ret;
}

int locdb_lookup(const char* buffer){
    struct in_addr a4;
    if(inet_pton(AF_INET,buffer,&a4)==1) return locdb_lookup4((unsigned char*)&a4.s_addr);
    struct in6_addr a6;
    if(inet_pton(AF_INET6,buffer,&a6)==1) return locdb_lookup6(a6.s6_addr,16,0);
    return -1;
}

int main(int argc,char* argv[]){
    if(argc<3){ fprintf(stderr,"usage: %s <db> <ip>...\n",argv[0]); return 1; }
    if(!locdb_open(argv[1])){ fprintf(stderr,"open failed\n"); return 1; }
    for(int i=2;i<argc;i++){
        int net=locdb_lookup(argv[i]);
        if(net<0){ printf("%-40s -> (no match)\n",argv[i]); continue; }
        unsigned char* p=locdb_data[DB_ND]+net*12;
        unsigned int asn=getint(p+4);
        unsigned int flags=(p[8]<<8)|p[9];   /* flags live at offset 8 */
        printf("%-40s -> CC=%c%c flags=0x%04x asn=%u\n",
               argv[i], p[0]?p[0]:'?', p[1]?p[1]:'?', flags, asn);
    }
    return 0;
}
