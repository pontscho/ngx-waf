
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

static unsigned short cc_map[32*32]; // 10bit key, 2kbyte memory usage

static inline unsigned int getint(unsigned char* p){
    return (p[0]<<24) | (p[1]<<16) | (p[2]<<8) | p[3];
}

static inline unsigned char* getstr(int pos){
    if( pos<0 || pos>=locdb_len[DB_PO] ) return NULL;
    return locdb_data[DB_PO]+pos;
}

int locdb_open(char* fn){
    unsigned char magic[8];
    unsigned char header[64];
    FILE* f=fopen(fn,"r");
    if(fread(magic,sizeof(magic),1,f)<1) return 0; // read error
    // Magic: 4C4F4344  42585801
    // printf("Magic: %08X  %08X\n",getint(magic),getint(magic+4));
    if(getint(magic)!=0x4C4F4344 || getint(magic+4)!=0x42585801) return 0; // bad format
    if(fread(header,sizeof(header),1,f)<1) return 0; // read error
    int i;
    for(i=0;i<5;i++){
        unsigned int off=getint(header+20+i*8);
        unsigned int len=getint(header+24+i*8);
//        printf("Block #%d: %u  %u\n",i,off,len);
        fseek(f,off,SEEK_SET);
        locdb_data[i]=malloc(len);
        if(!locdb_data[i]) return 0; // malloc error
        if(len!=fread(locdb_data[i],1,len,f)) return 0; // read error
        locdb_len[i]=len;
    }
#if DEBUG
    printf("Vendor: %s\n",getstr(getint(header+8)));
    printf("Descr: %s\n",getstr(getint(header+12)));
    printf("License: %s\n",getstr(getint(header+16)));
#endif
    // find IPv4 root-node:
    unsigned int nxt=0;
    for(i=0;i<96;i++){
        if(nxt*12>=locdb_len[DB_NT]) return 0; // out of bounds indexing...
        nxt=getint( locdb_data[DB_NT]+12*nxt+(i<80?0:4) );
    }
    ipv4root=nxt;
//    printf("IPv4 root-node: %d\n",nxt);

    // CC map:
    memset(cc_map,0xFF,sizeof(cc_map));
    i=0;
    unsigned char* p=locdb_data[DB_CO];
    unsigned char* pend=p+locdb_len[DB_CO];
    for(;p<pend;p+=8){
        int key=p[0]^((p[1]&31)<<5); // 10 bit
        if(cc_map[key]!=0xFFFF) printf("cc cache key collision: %d\n",i);
        cc_map[key]=i++;
    }
    return 1; // OK
}

// address -> net
int locdb_lookup6(unsigned char* address, int addrlen, unsigned int nxt){
    int ret=-1;
    int mask=0;
    do{ nxt*=12;
        if(nxt>=locdb_len[DB_NT]) return -1; // out of bounds indexing...
        unsigned int net=getint( locdb_data[DB_NT] + nxt + 8 );
        if(!(net&0x80000000)) ret=net;
        if(mask>>3>=addrlen) break; // no more bits available
        int bit=(address[mask>>3] >> (7-(mask&7)) )&1;
        mask++;
        nxt=getint( locdb_data[DB_NT] + nxt + bit*4 );
    } while(nxt);
    return ret;
}

int locdb_lookup4(unsigned char* ap){
    unsigned int address=(ap[0]<<24)|(ap[1]<<16)|(ap[2]<<8)|ap[3];
    int ret=-1;
    unsigned int nxt=ipv4root;
    for(int mask=0;mask<=32;mask++){
        nxt*=12;
        if(nxt>=locdb_len[DB_NT]) return -1; // out of bounds indexing...
        unsigned int net=getint( locdb_data[DB_NT] + nxt + 8 );
        if(!(net&0x80000000)) ret=net;
        int bit=(address>>29)&4; //  == 4*((address>>31)&1)
        nxt=getint( locdb_data[DB_NT] + nxt + bit );
        if(!nxt) break;
        address<<=1;
    }
    return ret;
}

int locdb_lookup(const char* buffer){
#if 1
    // quick & dirty ipv4 string parser :)
    unsigned char address4[4]={0,0,0,0};
    int len=0;
    const char* p=buffer;
    while(1){
        int c=*p++;
        if(!c && len==3) return locdb_lookup4(address4); // end of strings and we have 3 dots in it
        if(c=='.'){ if(++len>=4) break; } // max 3 dots! :)
        else if('0'<=c && c<='9'){ int x=(int)(address4[len])*10 + (c-'0'); if(x>255) break; address4[len]=x; }
        else break; // only dot & numbers are allowed here
    }
#else
    struct in_addr address4;
    if(inet_pton(AF_INET, buffer, &address4)==1) return locdb_lookup4((unsigned char *)(&address4.s_addr));
#endif
    struct in6_addr address6;
    if(inet_pton(AF_INET6, buffer, &address6)==1) return locdb_lookup6(address6.s6_addr,16,0);
    return -1;
}

// net -> asn (+cc)
unsigned int locdb_get_asn(unsigned int net,unsigned char* cc){
    if(net*12>=locdb_len[DB_ND]) return 0;
    if(cc) memcpy(cc,locdb_data[DB_ND]+net*12,2);
    return getint(locdb_data[DB_ND]+net*12+4);
}

// asn -> org
unsigned char* locdb_get_org(unsigned int asn){
    int p1=0;
    int p2=locdb_len[DB_AS]/8;
    while(p1<p2){
        int pos=(p1+p2)/2;   // binary search
        unsigned int x=getint(locdb_data[DB_AS]+pos*8);
        if(asn==x) return getstr(getint(locdb_data[DB_AS]+pos*8+4)); // found!
        if(asn<x) p2=pos; else p1=pos+1;
    }
    return NULL;
}

// cc -> country (+co[ntinent])
unsigned char* locdb_get_country(unsigned char* cc,unsigned char* co){
#if 1
    int key=cc[0]^((cc[1]&31)<<5); // 10 bit
    int x=8*cc_map[key];
    if(x<locdb_len[DB_CO]){
        if(co) memcpy(co,locdb_data[DB_CO]+x+2,2);
        return getstr(getint(locdb_data[DB_CO]+x+4));
    }
#else
    unsigned char* p=locdb_data[DB_CO];
    unsigned char* pend=p+locdb_len[DB_CO];
    for(;p<pend;p+=8){
        if(p[0]==cc[0] && p[1]==cc[1]){ // found!
            if(co) memcpy(co,p+2,2);
            return getstr(getint(p+4));
        }
    }
#endif
    return NULL;
}

int main(int argc,char* argv[]){
    locdb_open("/var/lib/location/database.db.JO");
//    unsigned char addr[]={193,224,41,5};
    //unsigned char addr[]={0x2a,1,0x6e,0xe0, 0,1, 2,1,   0,0,0,0,0xB,0xAD,0xC0,0xDE};
    //int ret=locdb_lookup6(addr,sizeof(addr),(sizeof(addr)<=4 ? ipv4root : 0));
    int ret=locdb_lookup("2a01:6ee0:1:201::bad:c0de");
//    int ret=locdb_lookup("193.224.41.5");
//    int ret=locdb_lookup((argc>1)?argv[1]:"66.66.66.66");
    unsigned char cc[3]={0,0,0};
    unsigned char co[3]={0,0,0};
    int asn=locdb_get_asn(ret,cc);
    unsigned char* country=locdb_get_country(cc,co);
    unsigned char* org=locdb_get_org(asn);
    printf("Result: net=%d  asn=%d  CC=%s/%s '%s'  ORG='%s'\n",ret,asn,cc,co,country,org);

#if 0
    // benchmark!
    srand(1978);
    char buffer[1024];
    for(int i=0;i<10000000;i++){
        unsigned int x=(rand()<<2)&0xFFFFFFFF;
        sprintf(buffer,"%d.%d.%d.%d",(x>>24)&255,(x>>16)&255,(x>>8)&255,x&255);
        int ret=locdb_lookup(buffer);
        int asn=locdb_get_asn(ret,cc);
        unsigned char* country=locdb_get_country(cc,co);
        unsigned char* org=locdb_get_org(asn);
        if(i<25) printf("%s:  net=%d  asn=%d  CC=%s/%s '%s'  ORG='%s'\n",buffer,ret,asn,cc,co,country,org);
    }
#endif

}

