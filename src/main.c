#define _GNU_SOURCE
#include <arpa/inet.h>
#include <crypt.h>
#include <openssl/sha.h>
#include <pty.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include "terminal.inc"
#define REQ_MAX 16384
#define NAME_MAX_SAFE 64
#define SESSIONS 128
#define SESSION_TTL 1800
static volatile sig_atomic_t stopping = 0;
static char bind_addr[64] = "127.0.0.1";
static int listen_port = 8088;
static char auth_path[256] = "/etc/lxc-dashboard/auth";
static char auth_user[128], auth_hash[256];
static unsigned failures = 0;
static time_t last_failure = 0;
struct session {
    char token[65];
    time_t expires;
};
static struct session sessions[SESSIONS];
static void on_signal(int sig) {
    (void)sig;
    stopping = 1;
}
static void copy_s(char *dst, size_t cap, const char *src) {
    if (!cap) return;
    if (!src) src = "";
    size_t i = 0;
    while (i + 1 < cap && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}
static bool valid_name(const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (n < 1 || n > 63) return false;
    if (!((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z') ||
    (s[0] >= '0' && s[0] <= '9'))) return false;
    for (size_t i=1; i<n; i++) {
        char c=s[i];
        if (!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-')) return false;
    }
    return true;
}
static int read_auth(void) {
    struct stat st;
    if (stat(auth_path, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 077) != 0) {
        fprintf(stderr, "auth file must exist and have mode 0600 or stricter: %s\n", auth_path);
        return -1;
    }
    FILE *f=fopen(auth_path,"r");
    if(!f) return -1;
    char line[512];
    int ok=0;
    if (fgets(line,sizeof line,f)) {
        line[strcspn(line,"\r\n")]=0;
        char *sep=strchr(line,':');
        if(sep && sep!=line && sep[1]) {
            *sep=0;
            copy_s(auth_user,sizeof auth_user,line);
            copy_s(auth_hash,sizeof auth_hash,sep+1);
            ok=1;
        }
    }
    fclose(f);
    return ok?0:-1;
}
static void random_hex(char *out, size_t bytes) {
    unsigned char b[32];
    if(bytes>sizeof b) bytes=sizeof b;
    int fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC);
    ssize_t got=fd>=0?read(fd,b,bytes):-1;
    if(fd>=0) close(fd);
    if(got!=(ssize_t)bytes) {
        memset(b,0,bytes);
    }
    static const char h[]="0123456789abcdef";
    for(size_t i=0;i<bytes;i++) {
        out[i*2]=h[b[i]>>4];
        out[i*2+1]=h[b[i]&15];
    }
    out[bytes*2]=0;
}
static bool token_ok(const char *t) {
    if(!t || strlen(t)!=64) return false;
    time_t now=time(NULL);
    for(size_t i=0;i<SESSIONS;i++) {
        if(sessions[i].expires<now) sessions[i].token[0]=0;
        if(sessions[i].token[0] && strcmp(sessions[i].token,t)==0) {
            sessions[i].expires=now+SESSION_TTL;
            return true;
        }
    }
    return false;
}
static void new_session(char *out) {
    random_hex(out,32);
    size_t slot=0;
    time_t oldest=LONG_MAX;
    for(size_t i=0;i<SESSIONS;i++) {
        if(!sessions[i].token[0] || sessions[i].expires<time(NULL)) {
            slot=i;
            oldest=0;
            break;
        }
        if(sessions[i].expires<oldest) {
            oldest=sessions[i].expires;
            slot=i;
        }
    }
    copy_s(sessions[slot].token,sizeof sessions[slot].token,out);
    sessions[slot].expires=time(NULL)+SESSION_TTL;
}
static void reply(int fd,int code,const char *status,const char *type,const char *body,const char *extra) {
    char head[1024];
    size_t n=strlen(body);
    int k=snprintf(head,sizeof head,"HTTP/1.1 %d %s\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %zu\r\n"
    "Connection: close\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "X-Frame-Options: DENY\r\n"
    "Cache-Control: no-store\r\n"
    "%s\r\n",code,status,type,n,extra?extra:"");
    if(k>0 && (size_t)k<sizeof head) {
        (void)send(fd,head,(size_t)k,MSG_NOSIGNAL);
        (void)send(fd,body,n,MSG_NOSIGNAL);
    }
}
static void json_error(int fd,int code,const char *msg) {
    char b[512];
    snprintf(b,sizeof b,"{\"error\":\"%s\"}",msg);
    reply(fd,code,code==401?"Unauthorized":code==400?"Bad Request":"Internal Server Error","application/json",b,NULL);
}
static int run_capture(char *const argv[], char *out,size_t cap) {
    int p[2];
    if(pipe(p)) return -1;
    pid_t pid=fork();
    if(pid<0) {
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if(pid==0) {
        dup2(p[1],STDOUT_FILENO);
        dup2(p[1],STDERR_FILENO);
        close(p[0]);
        close(p[1]);
        clearenv();
        setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1);
        execv(argv[0],argv);
        _exit(127);
    }
    close(p[1]);
    size_t used=0;
    while(used+1<cap) {
        ssize_t n=read(p[0],out+used,cap-used-1);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)break;
        used+=(size_t)n;
    }
    out[used]=0;
    close(p[0]);
    int st=0;
    while(waitpid(pid,&st,0)<0&&errno==EINTR) {
    }
    return WIFEXITED(st)?WEXITSTATUS(st):-1;
}
static void json_escape(char *out,size_t cap,const char *in) {
    size_t j=0;
    for(size_t i=0;in[i]&&j+6<cap;i++) {
        unsigned char c=(unsigned char)in[i];
        if(c=='"'||c=='\\') {
            out[j++]='\\';
            out[j++]=(char)c;
        } else if(c=='\n') {
            out[j++]='\\'; out[j++]='n';
        } else if(c=='\r') {
            out[j++]='\\'; out[j++]='r';
        } else if(c=='\t') {
            out[j++]='\\'; out[j++]='t';
        } else if(c<32) {
            out[j++]='?';
        } else {
            out[j++]=(char)c;
        }
    }
    out[j]=0;
}
static void containers_json(int fd) {
    DIR *d=opendir("/var/lib/lxc");
    if(!d) {
        json_error(fd,500,"cannot list /var/lib/lxc");
        return;
    }
    char out[12000]="[\"";
    out[1]=0;
    bool first=true;
    struct dirent *e;
    while((e=readdir(d))) {
        if(e->d_name[0]=='.'||!valid_name(e->d_name))continue;
        char name[64],cmdout[1024],escaped[256],state[64]="UNKNOWN",ip[128]="";
        copy_s(name,sizeof name,e->d_name);
        char *av[]= {
            "/usr/bin/lxc-info","-n",name,NULL
        };
        if(access(av[0],X_OK)!=0) av[0]="/usr/sbin/lxc-info";
        (void)run_capture(av,cmdout,sizeof cmdout);
        char *p=strstr(cmdout,"State:");
        if(p) {
            p+=6;
            while(*p==' '||*p=='\t')p++;
            size_t z=strcspn(p,"\r\n");
            if(z<sizeof state) {
                memcpy(state,p,z);
                state[z]=0;
            }
        }
        p=strstr(cmdout,"IP:");
        if(p) {
            p+=3;
            while(*p==' '||*p=='\t')p++;
            size_t z=strcspn(p,"\r\n");
            if(z<sizeof ip) {
                memcpy(ip,p,z);
                ip[z]=0;
            }
        }
        json_escape(escaped,sizeof escaped,name);
        char item[512];
        snprintf(item,sizeof item,"%s{\"name\":\"%s\",\"state\":\"%s\",\"ip\":\"%s\"}",first?"":",",escaped,state,ip);
        if(strlen(out)+strlen(item)+2<sizeof out)strcat(out,item);
        first=false;
    }
    closedir(d);
    strncat(out,"]",sizeof out-strlen(out)-1);
    reply(fd,200,"OK","application/json",out,NULL);
}
static bool get_form(const char *body,const char *key,char *out,size_t cap) {
    char needle[80];
    if(snprintf(needle,sizeof needle,"%s=",key)>=(int)sizeof needle)return false;
    const char *p=body;
    while(*p) {
        const char *end=strchr(p,'&');
        size_t n=end?(size_t)(end-p):strlen(p);
        if(n>=strlen(needle)&&strncmp(p,needle,strlen(needle))==0) {
            size_t j=0;
            p+=strlen(needle);
            while(*p && *p!='&' && j+1<cap) {
                char c=*p++;
                if(c=='+')c=' ';
                else if(c=='%'&&p[0]&&p[1]) {
                    char h[3]= {
                        p[0],p[1],0
                    };
                    c=(char)strtol(h,NULL,16);
                    p+=2;
                }
                out[j++]=c;
            }
            out[j]=0;
            return true;
        }
        if(!end) break;
        p=end+1;
    }
    return false;
}
static void handle(int fd) {
    struct timeval tv= {
        .tv_sec=5,.tv_usec=0
    };
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    char req[REQ_MAX+1];
    size_t used=0;
    ssize_t n;
    while(used<REQ_MAX) {
        n=recv(fd,req+used,REQ_MAX-used,0);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)break;
        used+=(size_t)n;
        req[used]=0;
        if(strstr(req,"\r\n"
        "\r\n"))break;
    }
    if(!used) return;
    req[used]=0;
    char method[8],path[256];
    if(sscanf(req,"%7s %255s",method,path)!=2) {
        json_error(fd,400,"bad request");
        return;
    }
    char *hend=strstr(req,"\r\n"
    "\r\n");
    if(!hend) {
        json_error(fd,400,"headers too large");
        return;
    }
    size_t headlen=(size_t)(hend-req)+4;
    size_t content_len=0;
    char *cl=strcasestr(req,"Content-Length:");
    if(cl&&cl<hend) content_len=(size_t)strtoul(cl+15,NULL,10);
    if(content_len>4096 || headlen+content_len>REQ_MAX) {
        json_error(fd,400,"request too large");
        return;
    }
    while(used<headlen+content_len) {
        n=recv(fd,req+used,REQ_MAX-used,0);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)break;
        used+=(size_t)n;
    }
    req[used]=0;
    char *body=req+headlen;
    if(strcmp(path,"/login")==0 && strcmp(method,"POST")==0) {
        char u[128]="",pw[256]="";
        (void)get_form(body,"username",u,sizeof u);
        (void)get_form(body,"password",pw,sizeof pw);
        time_t now=time(NULL);
        if(failures>=5 && now-last_failure<5)sleep(2);
        char *hashed=crypt(pw,auth_hash);
        bool ok=hashed&&strcmp(u,auth_user)==0&&strcmp(hashed,auth_hash)==0;
        memset(pw,0,sizeof pw);
        if(!ok) {
            failures++;
            last_failure=time(NULL);
            reply(fd,401,"Unauthorized","application/json","{\"error\":\"invalid credentials\"}",NULL);
            return;
        }
        failures=0;
        char tok[65],extra[256];
        new_session(tok);
        snprintf(extra,sizeof extra,"Set-Cookie: lxc_session=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d\r\n",tok,SESSION_TTL);
        reply(fd,200,"OK","application/json","{\"ok\":true}",extra);
        return;
    }
    char tok[65]="";
    char *cookie=strcasestr(req,"Cookie:");
    if(cookie&&cookie<hend) {
        char *p=strstr(cookie,"lxc_session=");
        if(p) {
            p+=12;
            size_t z=strcspn(p,";\r\n");
            if(z==64) {
                memcpy(tok,p,64);
                tok[64]=0;
            }
        }
    }
    if(strcmp(path,"/")==0 && strcmp(method,"GET")==0) {
        if(token_ok(tok)) {
            const char *page="<!doctype html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            "<link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css\">\n"
            "<style>\n"
            ":root {\n"
            "  color-scheme: dark;\n"
            "  --bg: #171b20;\n"
            "  --panel: #20262d;\n"
            "  --panel-head: #252d35;\n"
            "  --line: #39434d;\n"
            "  --text: #e3e7eb;\n"
            "  --muted: #a4adb6;\n"
            "  --green: #8fc7a0;\n"
            "  --red: #e58b87;\n"
            "}\n"
            "* { box-sizing: border-box; }\n"
            "body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.45 system-ui, -apple-system, sans-serif; }\n"
            "button, input { font: inherit; }\n"
            "button { padding: 7px 11px; color: var(--text); background: #303942; border: 1px solid #4a5661; border-radius: 3px; cursor: pointer; }\n"
            "button:hover:not(:disabled) { background: #3a454f; }\n"
            "button:focus-visible, input:focus-visible { outline: 2px solid var(--green); outline-offset: 2px; }\n"
            "button:disabled { opacity: .45; cursor: not-allowed; }\n"
            ".button-primary { background: #315640; border-color: #527b60; }\n"
            ".button-primary:hover:not(:disabled) { background: #3a664a; }\n"
            ".button-danger { color: #ffc0bc; background: #482d30; border-color: #805053; }\n"
            ".app { max-width: 1380px; margin: 0 auto; padding: 24px; }\n"
            ".topbar { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding-bottom: 18px; border-bottom: 1px solid var(--line); }\n"
            ".brand h1 { margin: 0; font-size: 24px; font-weight: 600; letter-spacing: -.025em; }\n"
            ".brand p { margin: 4px 0 0; color: var(--muted); }\n"
            ".top-meta { color: var(--muted); font-size: 12px; }\n"
            ".toolbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin: 18px 0; }\n"
            ".toolbar p { margin: 0; color: var(--muted); }\n"
            ".toolbar-actions { display: flex; gap: 8px; }\n"
            ".layout { display: grid; grid-template-columns: minmax(270px, .8fr) minmax(0, 1.7fr); gap: 16px; align-items: start; }\n"
            ".stack { display: grid; gap: 16px; min-width: 0; }\n"
            ".panel { min-width: 0; overflow: hidden; background: var(--panel); border: 1px solid var(--line); border-radius: 4px; }\n"
            ".panel-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 13px 16px; background: var(--panel-head); border-bottom: 1px solid var(--line); }\n"
            ".panel-head h2 { margin: 0; font-size: 15px; font-weight: 600; }\n"
            ".panel-body { padding: 16px; }\n"
            ".count { color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; }\n"
            ".container-list { list-style: none; margin: 0; padding: 0; }\n"
            ".container-list li { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-bottom: 1px solid #313a43; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }\n"
            ".container-list li:last-child { border-bottom: 0; }\n"
            ".container-list li button { min-width: 88px; text-align: left; }\n"
            ".container-list li.selected { background: #29372e; }\n"
            ".container-list li.selected button { border-color: #648b70; }\n"
            ".empty-state { padding: 18px; color: var(--muted); }\n"
            ".detail-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }\n"
            ".metric { min-width: 0; padding: 11px; background: #191f25; border: 1px solid #39434d; }\n"
            ".metric-label { display: block; margin-bottom: 5px; color: var(--muted); font-size: 12px; }\n"
            ".metric-value { display: block; font: 13px/1.4 ui-monospace, SFMono-Regular, monospace; overflow-wrap: anywhere; }\n"
            ".state-pill { display: inline-flex; align-items: center; gap: 7px; }\n"
            ".state-pill:before { content: \"\"; width: 7px; height: 7px; flex: 0 0 7px; border-radius: 50%; background: #858e97; }\n"
            ".state-pill.running:before { background: var(--green); }\n"
            ".actions { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 14px; }\n"
            ".actions button { text-transform: capitalize; }\n"
            ".terminal-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }\n"
            ".terminal-status { color: var(--muted); font-size: 12px; }\n"
            ".terminal-status.connected { color: var(--green); }\n"
            "#terminal-shell { height: 410px; max-height: 60vh; min-height: 240px; padding: 9px; overflow: hidden; background: #111519; border: 1px solid #39434d; }\n"
            "#terminal { width: 100%; height: 100%; }\n"
            ".xterm { height: 100%; }\n"
            ".terminal-foot { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-top: 9px; color: var(--muted); font-size: 11px; }\n"
            ".terminal-foot code { color: var(--text); }\n"
            ".form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }\n"
            ".field { display: grid; gap: 5px; color: var(--muted); font-size: 12px; }\n"
            ".field input { width: 100%; min-width: 0; padding: 9px; color: var(--text); background: #171c21; border: 1px solid #4a5661; border-radius: 3px; }\n"
            ".form-actions { margin-top: 14px; }\n"
            ".message { margin: 14px 0 0; padding: 9px 11px; border-left: 3px solid var(--green); background: #202d25; overflow-wrap: anywhere; }\n"
            ".message:empty { display: none; }\n"
            ".message.error { border-color: var(--red); background: #332426; }\n"
            "footer { display: flex; justify-content: space-between; gap: 12px; margin-top: 22px; padding-top: 12px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }\n"
            "@media (max-width: 820px) { .app { padding: 16px; } .layout { grid-template-columns: 1fr; } }\n"
            "@media (max-width: 520px) { .app { padding: 12px; } .topbar, .toolbar { align-items: flex-start; flex-direction: column; } .toolbar-actions { flex-wrap: wrap; } .panel-head, .panel-body { padding: 12px; } .detail-grid, .form-grid { grid-template-columns: 1fr; } #terminal-shell { height: 350px; } footer { flex-direction: column; } }\n"
            "/* Compact, full-width host view */\n"
            ".app { width:100%; max-width:none; min-height:100vh; padding:12px 14px; margin:0; }\n"
            "button, input, select, .panel, .metric, #terminal-shell { border-radius:0 !important; }\n"
            "button, input, select { font:inherit; }\n"
            "button, select { padding:6px 9px; }\n"
            ".layout { grid-template-columns:minmax(250px, 22%) minmax(0, 1fr); gap:10px; }\n"
            ".stack { gap:10px; }\n"
            ".panel-head { padding:8px 10px; }\n"
            ".panel-head h2 { font-size:13px; }\n"
            ".panel-body { padding:10px; }\n"
            ".container-list { display:grid; grid-template-columns:repeat(auto-fill,minmax(112px,1fr)); gap:4px; padding:6px; }\n"
            ".container-list li { min-width:0; min-height:58px; display:flex; flex-direction:column; align-items:stretch; gap:3px; padding:6px 7px; background:#191e22; border:1px solid #363e44; font-size:11px; }\n"
            ".container-list li button { width:100%; min-width:0; padding:0; border:0; background:transparent; text-align:left; font-size:12px; font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }\n"
            ".container-list li button:hover { background:transparent; }\n"
            ".container-list li.selected { background:#26362c; border-color:#779781; }\n"
            ".container-state { font-size:10px; color:var(--muted); text-transform:lowercase; }\n"
            ".container-state.running { color:var(--green); }\n"
            ".empty-state { grid-column:1 / -1; padding:12px; }\n"
            ".detail-grid { gap:5px; } .metric { padding:7px 8px; }\n"
            ".metric-label { font-size:11px; margin-bottom:3px; } .metric-value { font-size:12px; }\n"
            ".actions { display:flex; align-items:center; gap:5px; margin-top:8px; }\n"
            ".actions select { min-width:0; max-width:220px; }\n"
            "#terminal-shell { height:calc(100vh - 310px); min-height:260px; max-height:760px; padding:5px; }\n"
            ".terminal-foot { margin-top:5px; font-size:10px; }\n"
            "details.create-details > summary { padding:8px 10px; background:var(--panel-head); cursor:pointer; font-size:13px; font-weight:600; list-style-position:inside; }\n"
            "details.create-details[open] > summary { border-bottom:1px solid var(--line); }\n"
            ".form-grid { gap:8px; } .field { gap:4px; font-size:11px; } .field input { padding:7px; } .form-actions { margin-top:9px; }\n"
            ".toolbar { margin:10px 0; } .toolbar p, .top-meta { font-size:12px; }\n"
            "footer { margin-top:12px; padding-top:7px; font-size:11px; }\n"
            "@media (min-width:1500px) { .layout { grid-template-columns:330px minmax(0,1fr); } }\n"
            "@media (max-width:800px) { .app { padding:8px; } .layout { grid-template-columns:1fr; } #terminal-shell { height:55vh; } }\n"
            "@media (max-width:500px) { .topbar,.toolbar { align-items:flex-start; flex-direction:column; } .toolbar-actions { flex-wrap:wrap; } .detail-grid,.form-grid { grid-template-columns:1fr; } #terminal-shell { height:45vh; } footer { flex-direction:column; } }\n"
            "</style>\n"
            "<script src=\"https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js\"></script>\n"
            "<script src=\"https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.js\"></script>\n"
            "<title>LXC Dashboard</title>\n"
            "</head>\n"
            "<body>\n"
            "<main class=\"app\">\n"
            "  <header class=\"topbar\">\n"
            "    <div class=\"brand\"><h1>LXC dashboard</h1><p>Manage containers on this host.</p></div>\n"
            "    <div class=\"top-meta\">Local host · OpenRC</div>\n"
            "  </header>\n"
            "  <div class=\"toolbar\"><p>Container inventory and controls</p><div class=\"toolbar-actions\"><button type=\"button\" id=\"refresh\">Refresh</button><button type=\"button\" id=\"logout\">Log out</button></div></div>\n"
            "  <div class=\"layout\">\n"
            "    <aside class=\"stack\">\n"
            "      <section class=\"panel\" aria-labelledby=\"containers-title\">\n"
            "        <div class=\"panel-head\"><h2 id=\"containers-title\">Containers</h2><span class=\"count\" id=\"container-count\">0</span></div>\n"
            "        <ul id=\"list\" class=\"container-list\"><li class=\"empty-state\">Loading inventory…</li></ul>\n"
            "      </section>\n"
            "      <section class=\"panel\" aria-labelledby=\"create-title\">\n"
            "        <details class=\"create-details\"><summary id=\"create-title\">Create container</summary>\n"
            "        <div class=\"panel-body\"><form id=\"create-form\">\n"
            "          <div class=\"form-grid\">\n"
            "            <label class=\"field\">Container name<input id=\"newname\" name=\"name\" required placeholder=\"e.g. web01\" autocomplete=\"off\"></label>\n"
            "            <label class=\"field\">Distribution<input id=\"newdistro\" name=\"distro\" value=\"gentoo\" required></label>\n"
            "            <label class=\"field\">Release<input id=\"newrelease\" name=\"release\" value=\"current\" required></label>\n"
            "            <label class=\"field\">Architecture<input id=\"newarch\" name=\"arch\" value=\"amd64\" required></label>\n"
            "          </div>\n"
            "          <div class=\"form-actions\"><button class=\"button-primary\" type=\"submit\">+ Create instance</button></div>\n"
            "        </form></div></details>\n"
            "      </section>\n"
            "    </aside>\n"
            "    <div class=\"stack\">\n"
            "      <section class=\"panel\" aria-labelledby=\"selected-title\">\n"
            "        <div class=\"panel-head\"><h2 id=\"selected-title\">Selected container</h2><span class=\"count\" id=\"selected-state\">No selection</span></div>\n"
            "        <div class=\"panel-body\">\n"
            "          <div class=\"detail-grid\">\n"
            "            <div class=\"metric\"><span class=\"metric-label\">Container</span><span class=\"metric-value\" id=\"selected-name\">None</span></div>\n"
            "            <div class=\"metric\"><span class=\"metric-label\">State</span><span class=\"metric-value state-pill\" id=\"selected-state-value\">—</span></div>\n"
            "            <div class=\"metric\"><span class=\"metric-label\">IP address</span><span class=\"metric-value\" id=\"selected-ip\">—</span></div>\n"
            "          </div>\n"
            "          <div class=\"actions\"><label for=\"action-select\" class=\"metric-label\">Action</label><select id=\"action-select\" disabled><option value=\"\">Choose action…</option><option value=\"start\">Start</option><option value=\"stop\">Stop</option><option value=\"restart\">Restart</option><option value=\"freeze\">Freeze</option><option value=\"unfreeze\">Unfreeze</option><option value=\"destroy\">Destroy</option></select><button id=\"run-action\" type=\"button\" disabled>Run</button></div>\n"
            "        </div>\n"
            "      </section>\n"
            "      <section class=\"panel terminal-panel\" aria-labelledby=\"terminal-title\">\n"
            "        <div class=\"panel-head\"><h2 id=\"terminal-title\">Terminal</h2><div class=\"terminal-controls\"><span id=\"terminal-status\" class=\"terminal-status\" role=\"status\">Select a running container</span><button class=\"button-primary\" id=\"terminal-connect\" type=\"button\" disabled>Connect terminal</button></div></div>\n"
            "        <div class=\"panel-body\"><div id=\"terminal-shell\"><div id=\"terminal\" aria-label=\"Container terminal\"></div></div><div class=\"terminal-foot\"><span>Interactive shell</span><span>Scrollback: 3000 lines</span></div></div>\n"
            "      </section>\n"
            "      <p id=\"message\" class=\"message\" role=\"status\" aria-live=\"polite\"></p>\n"
            "    </div>\n"
            "  </div>\n"
            "  <footer><span>Gentoo Server · LXC dashboard</span><span>Browser terminal</span></footer>\n"
            "</main>\n"
            "<script>\n"
            "let selected = null;\n"
            "const byId = id => document.getElementById(id);\n"
            "async function api(url, body) {\n"
            "  const options = body === undefined ? {} : {\n"
            "    method: 'POST',\n"
            "    headers: {'Content-Type': 'application/x-www-form-urlencoded'},\n"
            "    body\n"
            "  };\n"
            "  const response = await fetch(url, options);\n"
            "  if (response.status === 401) { location.reload(); throw new Error('Login required'); }\n"
            "  const data = await response.json();\n"
            "  if (!response.ok) throw new Error(data.error || 'Request failed');\n"
            "  return data;\n"
            "}\n"
            "async function load() {\n"
            "  try {\n"
            "    const containers = await api('/api/containers');\n"
            "    const list = byId('list');\n"
            "    list.replaceChildren();\n"
            "    byId('container-count').textContent = containers.length;\n"
            "    if (!containers.length) {\n"
            "      const item = document.createElement('li');\n"
            "      item.textContent = 'No containers found.';\n"
            "      item.className = 'empty-state';\n"
            "      list.appendChild(item);\n"
            "    }\n"
            "    containers.forEach(container => {\n"
            "      const item = document.createElement('li');\n"
            "      const button = document.createElement('button');\n"
            "      button.type = 'button';\n"
            "      button.textContent = container.name;\n"
            "      if (selected && selected === container.name) item.className = 'selected';\n"
            "      button.addEventListener('click', () => show(container));\n"
            "      const state = document.createElement('span');\n"
            "      state.className = 'container-state' + (container.state === 'RUNNING' ? ' running' : '');\n"
            "      state.textContent = container.state.toLowerCase();\n"
            "      item.append(button, state);\n"
            "      list.appendChild(item);\n"
            "      if (selected && selected === container.name) show(container);\n"
            "    });\n"
            "    byId('message').textContent = '';\n"
            "  } catch (error) { byId('message').textContent = error.message; }\n"
            "}\n"
            "function show(container) {\n"
            "  selected = container.name;\n"
            "  byId('selected-name').textContent = container.name;\n"
            "  byId('selected-state').textContent = container.state;\n"
            "  byId('selected-state').className = 'count';\n"
            "  byId('selected-state-value').textContent = container.state;\n"
            "  byId('selected-state-value').className = 'metric-value state-pill' + (container.state === 'RUNNING' ? ' running' : '');\n"
            "  byId('selected-ip').textContent = container.ip || '-';\n"            "  byId('terminal-connect').disabled = container.state !== 'RUNNING';\n"
            "  byId('action-select').disabled = false;\n"
            "  byId('run-action').disabled = false;\n"
            "  byId('action-select').value = '';\n"
            "}\n"
            "async function act(action) {\n"
            "  if (!selected) return;\n"
            "  if (action === 'destroy' && !confirm('Permanently destroy ' + selected + '? This cannot be undone.')) return;\n"
            "  try {\n"
            "    await api('/api/action', 'name=' + encodeURIComponent(selected) + '&action=' + encodeURIComponent(action));\n"
            "    byId('message').textContent = 'Action completed: ' + action;\n"
            "    await load();\n"
            "  } catch (error) { byId('message').textContent = error.message; }\n"
            "}\n"
            "byId('run-action').addEventListener('click', () => { const action = byId('action-select').value; if (action) act(action); });\n"
            "byId('action-select').addEventListener('change', () => { byId('run-action').className = byId('action-select').value === 'destroy' ? 'button-danger' : ''; });\n"
            "byId('refresh').addEventListener('click', load);\n"
            "byId('logout').addEventListener('click', async () => {\n"
            "  await fetch('/logout', {method: 'POST'});\n"
            "  location.reload();\n"
            "});\n"
            "let terminalSocket = null;\n"
            "const terminal = new Terminal({cursorBlink:true,convertEol:true,scrollback:3000,fontSize:13,theme:{background:'#0b1020',foreground:'#e5e7eb',cursor:'#f8fafc',selectionBackground:'#334155'}});\n"
            "const fitAddon = new FitAddon.FitAddon();\n"
            "terminal.loadAddon(fitAddon);\n"
            "terminal.open(byId('terminal'));\n"
            "function sendTerminalSize() {\n"
            "  if (!terminalSocket || terminalSocket.readyState !== WebSocket.OPEN) return;\n"
            "  try { fitAddon.fit(); terminalSocket.send(JSON.stringify({type:'resize',cols:terminal.cols,rows:terminal.rows})); } catch (_) {}\n"
            "}\n"
            "if (typeof ResizeObserver !== 'undefined') new ResizeObserver(() => { try { fitAddon.fit(); sendTerminalSize(); } catch (_) {} }).observe(byId('terminal-shell'));\n"
            "terminal.onData(data => { if (terminalSocket && terminalSocket.readyState === WebSocket.OPEN) terminalSocket.send(data); });\n"
            "function connectTerminal() {\n"
            "  if (!selected || byId('selected-state').textContent.trim() !== 'RUNNING') { byId('terminal-status').textContent = 'Select a running container first.'; return; }\n"
            "  if (terminalSocket && (terminalSocket.readyState === WebSocket.OPEN || terminalSocket.readyState === WebSocket.CONNECTING)) { terminalSocket.close(); return; }\n"
            "  terminal.clear(); terminal.writeln('Connecting to ' + selected + '...');\n"
            "  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';\n"
            "  terminalSocket = new WebSocket(scheme + '//' + location.host + '/ws/terminal?name=' + encodeURIComponent(selected));\n"
            "  terminalSocket.binaryType = 'arraybuffer';\n"
            "  terminalSocket.onopen = () => { byId('terminal-status').textContent = 'Connected: ' + selected; byId('terminal-status').classList.add('connected'); byId('terminal-connect').textContent = 'Disconnect'; terminal.focus(); sendTerminalSize(); };\n"
            "  terminalSocket.onmessage = event => { if (typeof event.data === 'string') terminal.write(event.data); else terminal.write(new Uint8Array(event.data)); };\n"
            "  terminalSocket.onerror = () => { byId('terminal-status').textContent = 'Terminal connection error.'; };\n"
            "  terminalSocket.onclose = () => { byId('terminal-status').textContent = 'Disconnected'; byId('terminal-status').classList.remove('connected'); byId('terminal-connect').textContent = 'Connect terminal'; terminal.focus(); };\n"
            "}\n"
            "byId('terminal-connect').addEventListener('click', connectTerminal);\n"
            "terminal.onResize(({cols,rows}) => { if (terminalSocket && terminalSocket.readyState === WebSocket.OPEN) terminalSocket.send(JSON.stringify({type:'resize',cols,rows})); });\n"
            "byId('create-form').addEventListener('submit', async event => {\n"
            "  event.preventDefault();\n"
            "  const name = byId('newname').value.trim();\n"
            "  if (!confirm('Create container ' + name + '?')) return;\n"
            "  const values = ['name', 'distro', 'release', 'arch'].map(key =>\n"
            "    key + '=' + encodeURIComponent(byId('new' + key).value.trim()));\n"
            "  try {\n"
            "    await api('/api/create', values.join('&'));\n"
            "    byId('message').textContent = 'Container created.';\n"
            "    await load();\n"
            "  } catch (error) { byId('message').textContent = error.message; }\n"
            "});\n"
            "load();\n"
            "</script>\n"
            "</body>\n"
            "</html>";
            reply(fd,200,"OK","text/html; charset=utf-8",page,NULL);
        } else {
            const char *login="<!doctype html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            "<title>LXC Login</title>\n"
            "</head>\n"
            "<body>\n"
            "<h1>LXC Dashboard Login</h1>\n"
            "<form id=\"login-form\">\n"
            "<p><label>Username: <input name=\"username\" autocomplete=\"username\" required></label></p>\n"
            "<p><label>Password: <input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label></p>\n"
            "<p><button type=\"submit\">Log in</button></p>\n"
            "<p id=\"error\" role=\"alert\"></p>\n"
            "</form>\n"
            "<script>\n"
            "document.getElementById('login-form').addEventListener('submit', async event => {\n"
            "  event.preventDefault();\n"
            "  const form = event.currentTarget;\n"
            "  const response = await fetch('/login', {\n"
            "    method: 'POST',\n"
            "    headers: {'Content-Type': 'application/x-www-form-urlencoded'},\n"
            "    body: new URLSearchParams(new FormData(form))\n"
            "  });\n"
            "  if (response.ok) location.href = '/';\n"
            "  else document.getElementById('error').textContent = 'Login failed. Check your username and password.';\n"
            "});\n"
            "</script>\n"
            "</body>\n"
            "</html>";
            reply(fd,200,"OK","text/html; charset=utf-8",login,NULL);
        }
        return;
    }
    if(strcmp(path,"/login")==0) {
        json_error(fd,405,"method not allowed");
        return;
    }
    if(!token_ok(tok)) {
        json_error(fd,401,"login required");
        return;
    }
    if(strcmp(method,"GET")==0 && strncmp(path,"/ws/terminal?name=",18)==0) {
        char name[NAME_MAX_SAFE], key[128]="";
        const char *np=path+18;
        size_t nn=strcspn(np,"&");
        if(nn==0||nn>=sizeof name) { json_error(fd,400,"invalid container"); return; }
        memcpy(name,np,nn);
        name[nn]=0;
        if(!valid_name(name)) { json_error(fd,400,"invalid container"); return; }
        char *kh=strcasestr(req,"Sec-WebSocket-Key:");
        if(kh&&kh<hend) {
            kh+=18;
            while(*kh==' '||*kh=='\t')kh++;
            size_t kn=strcspn(kh,"\r\n");
            if(kn<sizeof key) { memcpy(key,kh,kn); key[kn]=0; }
        }
        if(strlen(key)<20) { json_error(fd,400,"missing websocket key"); return; }
        pid_t worker=fork();
        if(worker<0) { json_error(fd,500,"cannot start terminal"); return; }
        if(worker==0) { terminal_worker(fd,name,key); close(fd); _exit(0); }
        return;
    }
    if(strcmp(path,"/api/containers")==0&&strcmp(method,"GET")==0) {
        containers_json(fd);
        return;
    }
    if(strcmp(path,"/api/terminal")==0&&strcmp(method,"POST")==0) {
        char name[64]="",command[2048]="";
        (void)get_form(body,"name",name,sizeof name);
        (void)get_form(body,"command",command,sizeof command);
        if(!valid_name(name)||!command[0]) {
            json_error(fd,400,"invalid container name or empty command");
            return;
        }
        char *av[]={
            "/usr/bin/lxc-attach","-n",name,"--","/bin/sh","-lc",command,NULL
        };
        if(access(av[0],X_OK)!=0)av[0]="/usr/sbin/lxc-attach";
        char output[4096]="",escaped[10000],response[11000];
        int exit_code=run_capture(av,output,sizeof output);
        if(exit_code<0) {
            json_error(fd,500,"could not run lxc-attach");
            return;
        }
        json_escape(escaped,sizeof escaped,output);
        snprintf(response,sizeof response,"{\"output\":\"%s\",\"exit_code\":%d}",escaped,exit_code);
        reply(fd,200,"OK","application/json",response,NULL);
        return;
    }
    if(strcmp(path,"/logout")==0) {
        for(size_t i=0;i<SESSIONS;i++)if(tok[0]&&strcmp(tok,sessions[i].token)==0)sessions[i].token[0]=0;
        reply(fd,200,"OK","application/json","{\"ok\":true}","Set-Cookie: lxc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0\r\n");
        return;
    }
    if(strcmp(path,"/api/action")==0&&strcmp(method,"POST")==0) {
        char name[64]="",action[32]="";
        (void)get_form(body,"name",name,sizeof name);
        (void)get_form(body,"action",action,sizeof action);
        if(!valid_name(name)) {
            json_error(fd,400,"invalid container name");
            return;
        }
        char *av[6]= {
            "/usr/bin/lxc-start","-n",name,NULL,NULL,NULL
        };
        if(strcmp(action,"start")==0) {
            av[0]=(char*)"/usr/bin/lxc-start";
            av[3]=(char*)"-d";
            av[4]=NULL;
        }
        else if(strcmp(action,"stop")==0) {
            av[0]=(char*)"/usr/bin/lxc-stop";
            av[3]=NULL;
        }
        else if(strcmp(action,"restart")==0) {
            av[0]=(char*)"/usr/bin/lxc-stop";
            av[3]=(char*)"--reboot";
        }
        else if(strcmp(action,"freeze")==0) {
            av[0]=(char*)"/usr/bin/lxc-freeze";
            av[3]=NULL;
        }
        else if(strcmp(action,"unfreeze")==0) {
            av[0]=(char*)"/usr/bin/lxc-unfreeze";
            av[3]=NULL;
        }
        else if(strcmp(action,"destroy")==0) {
            av[0]=(char*)"/usr/bin/lxc-destroy";
            av[3]=(char*)"-f";
        }
        else {
            json_error(fd,400,"unsupported action");
            return;
        }
        if(access(av[0],X_OK)!=0) {
            char alt[128];
            snprintf(alt,sizeof alt,"/usr/sbin/%s",strrchr(av[0],'/')+1);
            av[0]=strdup(alt);
            if(!av[0]) {
                json_error(fd,500,"out of memory");
                return;
            }
        }
        if(strcmp(action,"restart")==0) {
            av[4]=NULL;
        }
        pid_t pid=fork();
        if(pid==0) {
            clearenv();
            setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1);
            execv(av[0],av);
            _exit(127);
        }
        int st=0;
        if(pid<0||waitpid(pid,&st,0)<0||!WIFEXITED(st)||WEXITSTATUS(st)!=0) {
            json_error(fd,500,"container command failed");
            return;
        }
        reply(fd,200,"OK","application/json","{\"ok\":true}",NULL);
        return;
    }
    if(strcmp(path,"/api/create")==0&&strcmp(method,"POST")==0) {
        char name[64]="",distro[64]="",release[64]="",arch[64]="";
        (void)get_form(body,"name",name,sizeof name);
        (void)get_form(body,"distro",distro,sizeof distro);
        (void)get_form(body,"release",release,sizeof release);
        (void)get_form(body,"arch",arch,sizeof arch);
        if(!valid_name(name)||!valid_name(distro)||!valid_name(release)||!valid_name(arch)) {
            json_error(fd,400,"invalid name, distro, release, or architecture");
            return;
        }
        char *av[]= {
            "/usr/bin/lxc-create","-n",name,"-t","download","--","-d",distro,"-r",release,"-a",arch,NULL
        };
        if(access(av[0],X_OK)!=0)av[0]="/usr/sbin/lxc-create";
        pid_t pid=fork();
        if(pid==0) {
            clearenv();
            setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1);
            execv(av[0],av);
            _exit(127);
        }
        int st=0;
        if(pid<0||waitpid(pid,&st,0)<0||!WIFEXITED(st)||WEXITSTATUS(st)!=0) {
            json_error(fd,500,"container create failed (default Gentoo/current/amd64 template)");
            return;
        }
        reply(fd,200,"OK","application/json","{\"ok\":true}",NULL);
        return;
    }
    json_error(fd,404,"not found");
}
static int set_password(const char *path) {
    char user[128],*pw,*hash;
    fprintf(stderr,"Username: ");
    if(!fgets(user,sizeof user,stdin))return 1;
    user[strcspn(user,"\r\n")]=0;
    if(!*user||strchr(user,':')) {
        fprintf(stderr,"Invalid username\n");
        return 1;
    }
    pw=getpass("Password: ");
    if(!pw||strlen(pw)<12) {
        fprintf(stderr,"Use at least 12 characters\n");
        return 1;
    }
    char *salt=crypt_gensalt("$y$",0,NULL,0);
    if(!salt) {
        fprintf(stderr,"yescrypt unavailable in libcrypt\n");
        return 1;
    }
    hash=crypt(pw,salt);
    if(!hash) {
        fprintf(stderr,"Password hashing failed\n");
        return 1;
    }
    if(mkdir("/etc/lxc-dashboard",0700)&&errno!=EEXIST&&strncmp(path,"/etc/lxc-dashboard/",19)==0) {
        perror("mkdir");
        return 1;
    }
    int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);
    if(fd<0) {
        perror("open auth file");
        return 1;
    }
    if(fchmod(fd,0600)) {
        close(fd);
        return 1;
    }
    dprintf(fd,"%s:%s\n",user,hash);
    close(fd);
    memset(pw,0,strlen(pw));
    return 0;
}
int main(int argc,char **argv) {
    for(int i=1;i<argc;i++) {
        if(strcmp(argv[i],"--set-password")==0&&i+1<argc)return set_password(argv[++i]);
        if(strcmp(argv[i],"--bind")==0&&i+1<argc) {
            copy_s(bind_addr,sizeof bind_addr,argv[++i]);
            continue;
        }
        if(strcmp(argv[i],"--port")==0&&i+1<argc) {
            char *e=NULL;
            long v=strtol(argv[++i],&e,10);
            if(!e||*e||v<1||v>65535) {
                fprintf(stderr,"invalid port\n");
                return 2;
            }
            listen_port=(int)v;
            continue;
        }
        if(strcmp(argv[i],"--auth")==0&&i+1<argc) {
            copy_s(auth_path,sizeof auth_path,argv[++i]);
            continue;
        }
        fprintf(stderr,"Usage: %s [--bind ADDRESS] [--port PORT] [--auth FILE] | --set-password FILE\n",argv[0]);
        return 2;
    }
    if(read_auth()) {
        fprintf(stderr,"Cannot read credentials; run --set-password first\n");
        return 1;
    }
    signal(SIGPIPE,SIG_IGN);
    signal(SIGINT,on_signal);
    signal(SIGTERM,on_signal);
    int s=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    if(s<0) {
        perror("socket");
        return 1;
    }
    int one=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a= {
        .sin_family=AF_INET,.sin_port=htons((uint16_t)listen_port)
    };
    if(inet_pton(AF_INET,bind_addr,&a.sin_addr)!=1) {
        fprintf(stderr,"bind address must be IPv4 literal\n");
        close(s);
        return 2;
    }
    if(bind(s,(struct sockaddr*)&a,sizeof a)||listen(s,32)) {
        perror("bind/listen");
        close(s);
        return 1;
    }
    fprintf(stderr, "lxc-dashboard listening on %s:%d\n", bind_addr, listen_port);
    fprintf(stderr, "Press Ctrl+C to quit\n");
    while (!stopping) {
        struct pollfd pfd = {
            .fd = s,
            .events = POLLIN
        };
        int r = poll(&pfd, 1, 1000);
        /* Return on signal or after one second so we can re-check stopping. */
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (r == 0) continue;

        int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            if (stopping) break;
            perror("accept");
            continue;
        }
        handle(c);
        close(c);
    }
    fprintf(stderr, "shutting down\n");
    close(s);
    return 0;
}
