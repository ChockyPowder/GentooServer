static int send_all(int fd, const void *buf, size_t len) {
    const unsigned char *p=buf;
    while(len) {
        ssize_t n=send(fd,p,len,MSG_NOSIGNAL);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return -1;
        p+=(size_t)n; len-=(size_t)n;
    }
    return 0;
}
static int recv_exact(int fd, void *buf, size_t len) {
    unsigned char *p=buf;
    while(len) {
        ssize_t n=recv(fd,p,len,0);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return -1;
        p+=(size_t)n; len-=(size_t)n;
    }
    return 0;
}
static int ws_send(int fd, unsigned char opcode, const void *data, size_t len) {
    unsigned char h[4]; size_t hn=2;
    h[0]=(unsigned char)(0x80|opcode);
    if(len<126) h[1]=(unsigned char)len;
    else if(len<=65535) { h[1]=126; h[2]=(unsigned char)(len>>8); h[3]=(unsigned char)len; hn=4; }
    else return -1;
    if(send_all(fd,h,hn))return -1;
    return len?send_all(fd,data,len):0;
}
static int ws_read(int fd, unsigned char *opcode, unsigned char *data, size_t cap, size_t *outlen) {
    unsigned char h[2],ext[8],mask[4];
    if(recv_exact(fd,h,2))return -1;
    *opcode=(unsigned char)(h[0]&15);
    if((h[0]&0x70)!=0 || !(h[1]&0x80))return -1;
    uint64_t len=(uint64_t)(h[1]&127);
    if(len==126) { if(recv_exact(fd,ext,2))return -1; len=((uint64_t)ext[0]<<8)|ext[1]; }
    else if(len==127) { if(recv_exact(fd,ext,8))return -1; len=0; for(int i=0;i<8;i++)len=(len<<8)|ext[i]; }
    if(len>cap || len>65536)return -1;
    if(recv_exact(fd,mask,4)||recv_exact(fd,data,(size_t)len))return -1;
    for(size_t i=0;i<(size_t)len;i++)data[i]^=mask[i&3];
    *outlen=(size_t)len;
    return 0;
}
static void base64_encode(const unsigned char *in, size_t n, char *out) {
    static const char tab[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i=0,j=0;
    while(i<n) {
        size_t rem=n-i;
        unsigned a=in[i++], b=rem>1?in[i++]:0, c=rem>2?in[i++]:0;
        out[j++]=tab[a>>2];
        out[j++]=tab[((a&3)<<4)|(b>>4)];
        out[j++]=rem>1?tab[((b&15)<<2)|(c>>6)]:'=';
        out[j++]=rem>2?tab[c&63]:'=';
    }
    out[j]=0;
}
static void terminal_worker(int client, const char *name, const char *key) {
    struct timeval zero={0,0};
    (void)setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&zero,sizeof zero);
    char joined[256], accept_key[64], response[512];
    unsigned char digest[SHA_DIGEST_LENGTH];
    snprintf(joined,sizeof joined,"%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",key);
    SHA1((const unsigned char *)joined,strlen(joined),digest);
    base64_encode(digest,sizeof digest,accept_key);
    int n=snprintf(response,sizeof response,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",accept_key);
    if(n<=0||(size_t)n>=sizeof response||send_all(client,response,(size_t)n))return;
    struct winsize ws={.ws_row=24,.ws_col=80};
    int master=-1;
    pid_t child=forkpty(&master,NULL,NULL,&ws);
    if(child<0) { (void)ws_send(client,1,"Could not create terminal.\r\n",27); return; }
    if(child==0) {
        clearenv();
        setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1);
        setenv("TERM","xterm-256color",1);
        char *av[]={"/usr/bin/lxc-attach","-n",(char *)name,"--","/bin/sh","-l",NULL};
        execv(av[0],av);
        char *fallback[]={"/usr/sbin/lxc-attach","-n",(char *)name,"--","/bin/sh","-l",NULL};
        execv(fallback[0],fallback);
        _exit(127);
    }
    (void)fcntl(master,F_SETFL,fcntl(master,F_GETFL)|O_NONBLOCK);
    unsigned char buf[65536],opcode;
    bool alive=true;
    while(alive) {
        struct pollfd pf[2]={{.fd=client,.events=POLLIN},{.fd=master,.events=POLLIN}};
        int pr=poll(pf,2,-1);
        if(pr<0) { if(errno==EINTR)continue; break; }
        if(pf[0].revents&(POLLERR|POLLHUP|POLLNVAL))break;
        if(pf[0].revents&POLLIN) {
            size_t got=0;
            if(ws_read(client,&opcode,buf,sizeof buf,&got))break;
            if(opcode==8) { (void)ws_send(client,8,buf,got>125?0:got); break; }
            if(opcode==9) { if(ws_send(client,10,buf,got))break; }
            else if(opcode==1||opcode==2) {
                size_t off=0;
                while(off<got) {
                    ssize_t w=write(master,buf+off,got-off);
                    if(w<0&&errno==EINTR)continue;
                    if(w<0&&(errno==EAGAIN||errno==EWOULDBLOCK)) { usleep(1000); continue; }
                    if(w<=0) { alive=false; break; }
                    off+=(size_t)w;
                }
            }
        }
        if(pf[1].revents&POLLIN) {
            ssize_t got=read(master,buf,sizeof buf);
            if(got>0) { if(ws_send(client,2,buf,(size_t)got))break; }
            else if(got<0&&errno!=EINTR&&errno!=EAGAIN&&errno!=EWOULDBLOCK)break;
        }
        if(pf[1].revents&(POLLERR|POLLHUP|POLLNVAL))break;
    }
    close(master);
    kill(child,SIGHUP);
    while(waitpid(child,NULL,0)<0&&errno==EINTR){}
}
