/*
  sb2mqtt.c — Poll Arris SB8200 status page via lynx, parse tables,
  publish Home Assistant MQTT Discovery + sensor states.

  Key features:
  - Runs 24/7 loop
  - Polls via: lynx --dump -nolist --width=200 <url>
  - Parses:
      * Startup Procedure (Connectivity State)
      * Downstream Bonded Channels (lock, modulation, freq, power, snr, corrected, uncorrectables)
      * Upstream Bonded Channels (channel, channel_id, lock, type, freq, width, power)
  - Publishes Home Assistant MQTT Discovery (retained)
  - Publishes states (retained by default) under base_topic
  - Uses /etc/sb2mqtt.ini by default
  - Reloads INI automatically when it changes (mtime):
      * Reconnects to MQTT if MQTT settings changed
      * Republishes HA discovery if HA/channel settings changed
      * Reopens log file if log path changed
  - Re-publishes HA discovery every 30 minutes (retained configs)

  Build:
    sudo apt install -y build-essential lynx libmosquitto-dev
    gcc -O2 -Wall -Wextra -o sb2mqtt sb2mqtt.c -lmosquitto

  Run:
    sudo ./sb2mqtt
    sudo ./sb2mqtt --ini /etc/sb2mqtt.ini
*/

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <mosquitto.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   // strcasecmp
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---------------- signals / globals ---------------- */

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_mqtt_up = 0;

static void on_sig(int sig){ (void)sig; g_stop = 1; }

static void on_mqtt_connect(struct mosquitto *m, void *obj, int rc){
    (void)m; (void)obj;
    g_mqtt_up = (rc == 0) ? 1 : 0;
}
static void on_mqtt_disconnect(struct mosquitto *m, void *obj, int rc){
    (void)m; (void)obj; (void)rc;
    g_mqtt_up = 0;
}

/* ---------------- small utils ---------------- */

/*
  Safe bounded string copy that:
    - copies at most dstsz-1 bytes
    - always NUL-terminates
    - avoids strncpy() truncation warnings
*/
static void scpy(char *dst, size_t dstsz, const char *src){
    if(!dst || dstsz == 0) return;
    if(!src){ dst[0] = 0; return; }
    size_t n = strnlen(src, dstsz - 1);
    memcpy(dst, src, n);
    dst[n] = 0;
}

static void log_msg(FILE *lf, const char *fmt, ...) {
    if(!lf) return;
    time_t now=time(NULL);
    struct tm tm; localtime_r(&now,&tm);
    char ts[64]; strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",&tm);
    fprintf(lf,"[%s] ",ts);
    va_list ap; va_start(ap,fmt); vfprintf(lf,fmt,ap); va_end(ap);
    fputc('\n',lf); fflush(lf);
}

static void rstrip(char *s){
    size_t n=strlen(s);
    while(n && (s[n-1]=='\n'||s[n-1]=='\r'||isspace((unsigned char)s[n-1]))){ s[n-1]=0; n--; }
}
static char *lstrip(char *s){ while(*s && isspace((unsigned char)*s)) s++; return s; }
static bool starts_with(const char *s,const char *pfx){ return strncmp(s,pfx,strlen(pfx))==0; }

static void trim_inplace(char *s){
    rstrip(s);
    char *p=lstrip(s);
    if(p!=s) memmove(s,p,strlen(p)+1);
}

static long parse_hz_token(const char *tok){
    char *end=NULL;
    long v=strtol(tok,&end,10);
    if(end==tok) return -1;
    return v;
}
static double parse_double_token(const char *tok){
    char *end=NULL;
    double v=strtod(tok, &end);
    if(end==tok) return 0.0;
    return v;
}
static long long parse_ll_token(const char *tok){
    char *end=NULL;
    long long v=strtoll(tok, &end, 10);
    if(end==tok) return 0;
    return v;
}

static int make_dirs_for_file(const char *path) {
    char *tmp = strdup(path ? path : "");
    if (!tmp) return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    free(tmp);
    return 0;
}

static bool files_equal_str(const char *a, const char *b){
    if(!a && !b) return true;
    if(!a || !b) return false;
    return strcmp(a,b)==0;
}

/* ---------------- INI config ---------------- */

typedef struct {
    // poll
    char url[256];
    int interval_sec;
    int timeout_sec;

    // mqtt
    char mqtt_host[128];
    int mqtt_port;
    char mqtt_user[128];
    char mqtt_pass[128];
    char mqtt_client_id[128];
    int mqtt_qos;
    bool mqtt_retain_state;

    // ha
    char ha_prefix[128];
    char device_name[128];
    char device_id[128];
    char base_topic[128];

    // channel filters
    int down_ids[128]; int down_n;
    int up_ids[32]; int up_n;

    // logging
    char log_path[256];

    // ini reload check interval (seconds)
    int ini_check_sec;
} Config;

static void cfg_defaults(Config *c){
    memset(c,0,sizeof(*c));

    // Poll defaults (SB8200 can be slow)
    scpy(c->url, sizeof(c->url), "http://192.168.100.1/");
    c->interval_sec = 90;
    c->timeout_sec  = 60;

    // MQTT defaults
    scpy(c->mqtt_host, sizeof(c->mqtt_host), "127.0.0.1");
    c->mqtt_port = 1883;
    c->mqtt_qos = 1;
    c->mqtt_retain_state = true;
    scpy(c->mqtt_client_id, sizeof(c->mqtt_client_id), "sb2mqtt");

    // HA defaults (as requested)
    scpy(c->ha_prefix, sizeof(c->ha_prefix), "homeassistant");
    scpy(c->device_name, sizeof(c->device_name), "SB8200 Modem");
    scpy(c->device_id, sizeof(c->device_id), "sb8200");
    scpy(c->base_topic, sizeof(c->base_topic), "sb2mqtt");

    // Logging
    scpy(c->log_path, sizeof(c->log_path), "/var/log/sb2mqtt.log");

    // INI reload check interval
    c->ini_check_sec = 15;
}

static void parse_csv_ints(const char *s, int *arr, int *n, int maxn){
    *n = 0;
    if(!s) return;
    while(*s){
        while(*s && (isspace((unsigned char)*s) || *s==',')) s++;
        if(!*s) break;
        char *end=NULL;
        long v=strtol(s,&end,10);
        if(end==s) break;
        if(*n < maxn) arr[(*n)++] = (int)v;
        s=end;
        while(*s && *s!=',') s++;
    }
}

static int cfg_load_ini(Config *c, const char *path, FILE *lf){
    FILE *f=fopen(path,"r");
    if(!f){
        log_msg(lf,"INI not found (%s): %s (using defaults)", path, strerror(errno));
        return -1;
    }
    char section[64]="";
    char line[512];

    while(fgets(line,sizeof(line),f)){
        rstrip(line);
        char *s=lstrip(line);
        if(!*s || *s==';' || *s=='#') continue;

        if(*s=='['){
            char *e=strchr(s,']');
            if(!e) continue;
            *e=0;
            scpy(section, sizeof(section), s+1);
            continue;
        }

        char *eq=strchr(s,'=');
        if(!eq) continue;
        *eq=0;

        char key[256], val[512];
        scpy(key, sizeof(key), s);
        scpy(val, sizeof(val), eq+1);
        trim_inplace(key);
        trim_inplace(val);

        if(strcmp(section,"poll")==0){
            if(strcmp(key,"url")==0) scpy(c->url,sizeof(c->url),val);
            else if(strcmp(key,"interval_sec")==0) c->interval_sec = atoi(val);
            else if(strcmp(key,"timeout_sec")==0) c->timeout_sec = atoi(val);
        } else if(strcmp(section,"mqtt")==0){
            if(strcmp(key,"host")==0) scpy(c->mqtt_host,sizeof(c->mqtt_host),val);
            else if(strcmp(key,"port")==0) c->mqtt_port = atoi(val);
            else if(strcmp(key,"username")==0) scpy(c->mqtt_user,sizeof(c->mqtt_user),val);
            else if(strcmp(key,"password")==0) scpy(c->mqtt_pass,sizeof(c->mqtt_pass),val);
            else if(strcmp(key,"client_id")==0) scpy(c->mqtt_client_id,sizeof(c->mqtt_client_id),val);
            else if(strcmp(key,"qos")==0) c->mqtt_qos = atoi(val);
            else if(strcmp(key,"retain_state")==0) c->mqtt_retain_state =
                (strcasecmp(val,"true")==0 || strcmp(val,"1")==0 || strcasecmp(val,"yes")==0);
        } else if(strcmp(section,"ha")==0){
            if(strcmp(key,"discovery_prefix")==0) scpy(c->ha_prefix,sizeof(c->ha_prefix),val);
            else if(strcmp(key,"device_name")==0) scpy(c->device_name,sizeof(c->device_name),val);
            else if(strcmp(key,"device_id")==0) scpy(c->device_id,sizeof(c->device_id),val);
            else if(strcmp(key,"base_topic")==0) scpy(c->base_topic,sizeof(c->base_topic),val);
        } else if(strcmp(section,"channels")==0){
            if(strcmp(key,"downstream_ids")==0) parse_csv_ints(val, c->down_ids, &c->down_n, 128);
            else if(strcmp(key,"upstream_ids")==0) parse_csv_ints(val, c->up_ids, &c->up_n, 32);
        } else if(strcmp(section,"log")==0){
            if(strcmp(key,"path")==0) scpy(c->log_path,sizeof(c->log_path),val);
        } else if(strcmp(section,"ini")==0){
            if(strcmp(key,"check_sec")==0) c->ini_check_sec = atoi(val);
        }
    }

    fclose(f);

    if(c->interval_sec < 5) c->interval_sec = 5;
    if(c->timeout_sec < 5) c->timeout_sec = 5;
    if(c->mqtt_qos < 0) c->mqtt_qos = 0;
    if(c->mqtt_qos > 2) c->mqtt_qos = 2;
    if(c->ini_check_sec < 1) c->ini_check_sec = 1;

    // Keep timeout < interval to avoid overlap/back-to-back pressure
    if(c->timeout_sec >= c->interval_sec){
        c->timeout_sec = c->interval_sec - 5;
        if(c->timeout_sec < 5) c->timeout_sec = 5;
    }

    return 0;
}

static bool id_in_list(int id, const int *list, int n){
    if(n <= 0) return true; // empty list => allow all
    for(int i=0;i<n;i++) if(list[i]==id) return true;
    return false;
}

static bool int_lists_equal(const int *a, int an, const int *b, int bn){
    if(an != bn) return false;
    for(int i=0;i<an;i++){
        if(a[i] != b[i]) return false;
    }
    return true;
}

/* ---------------- run lynx + capture output ---------------- */

static int run_lynx_capture(const char *url, int timeout_sec, char **out, size_t *outlen, FILE *lf){
    *out=NULL; *outlen=0;

    int pipefd[2];
    if(pipe(pipefd)!=0){
        log_msg(lf,"pipe() failed: %s",strerror(errno));
        return -1;
    }

    pid_t pid=fork();
    if(pid<0){
        log_msg(lf,"fork() failed: %s",strerror(errno));
        close(pipefd[0]); close(pipefd[1]);
        return -1;
    }

    if(pid==0){
        dup2(pipefd[1],STDOUT_FILENO);
        dup2(pipefd[1],STDERR_FILENO);
        close(pipefd[0]); close(pipefd[1]);
        char *const argv[]={
            "lynx","--dump","-nolist","--width=200",(char*)url,NULL
        };
        execvp("lynx",argv);
        _exit(127);
    }

    close(pipefd[1]);

    int flags=fcntl(pipefd[0],F_GETFL,0);
    fcntl(pipefd[0],F_SETFL,flags|O_NONBLOCK);

    size_t cap=64*1024;
    char *buf=malloc(cap);
    if(!buf){
        log_msg(lf,"malloc failed");
        close(pipefd[0]);
        kill(pid,SIGKILL);
        waitpid(pid,NULL,0);
        return -1;
    }

    size_t len=0;
    time_t start=time(NULL);

    while(1){
        if(g_stop) break;

        time_t now=time(NULL);
        if(timeout_sec>0 && (int)(now-start)>=timeout_sec){
            log_msg(lf,"lynx timed out after %ds, killing pid %d",timeout_sec,pid);
            kill(pid,SIGKILL);
            break;
        }

        fd_set rfds; FD_ZERO(&rfds); FD_SET(pipefd[0],&rfds);
        struct timeval tv={ .tv_sec=1, .tv_usec=0 };

        int sel=select(pipefd[0]+1,&rfds,NULL,NULL,&tv);
        if(sel<0){
            if(errno==EINTR) continue;
            log_msg(lf,"select() failed: %s",strerror(errno));
            break;
        }

        if(sel==0){
            int st;
            pid_t w=waitpid(pid,&st,WNOHANG);
            if(w==pid){
                while(1){
                    char tmp[4096];
                    ssize_t r=read(pipefd[0],tmp,sizeof(tmp));
                    if(r<=0) break;
                    if(len+(size_t)r+1>cap){
                        cap=(cap*2)+(size_t)r+1;
                        char *nb=realloc(buf,cap);
                        if(!nb) break;
                        buf=nb;
                    }
                    memcpy(buf+len,tmp,(size_t)r);
                    len+=(size_t)r;
                }
                break;
            }
            continue;
        }

        if(FD_ISSET(pipefd[0],&rfds)){
            char tmp[4096];
            ssize_t r=read(pipefd[0],tmp,sizeof(tmp));
            if(r>0){
                if(len+(size_t)r+1>cap){
                    cap=(cap*2)+(size_t)r+1;
                    char *nb=realloc(buf,cap);
                    if(!nb){ log_msg(lf,"realloc failed"); break; }
                    buf=nb;
                }
                memcpy(buf+len,tmp,(size_t)r);
                len+=(size_t)r;
            } else if(r==0){
                break;
            } else {
                if(errno!=EAGAIN && errno!=EWOULDBLOCK){
                    log_msg(lf,"read() failed: %s",strerror(errno));
                    break;
                }
            }
        }
    }

    close(pipefd[0]);
    int st=0; waitpid(pid,&st,0);

    buf[len]=0;
    *out=buf; *outlen=len;
    return 0;
}

/* ---------------- parsing model ---------------- */

typedef struct {
    char procedure[128];
    char status[64];
    char comment[128];
} StartupRow;

typedef struct {
    int channel_id;
    char lock_status[32];
    char modulation[32];
    long freq_hz;
    double power_dbmv;
    double snr_db;
    long long corrected;
    long long uncorrectables;
} DownRow;

typedef struct {
    int channel;
    int channel_id;
    char lock_status[32];
    char us_type[32];
    long freq_hz;
    long width_hz;
    double power_dbmv;
} UpRow;

typedef struct {
    StartupRow startup[32]; int startup_n;
    DownRow down[96]; int down_n;
    UpRow up[32]; int up_n;

    char current_system_time[128];
    char connectivity_state_status[64];
    char connectivity_state_comment[128];
} Parsed;

static void parsed_init(Parsed *p){ memset(p,0,sizeof(*p)); }

/*
  Split cols by "2+ spaces" (lynx table formatting).
*/
static int split_cols_2spaces(char *line, char *cols[], int maxcols){
    int n=0;
    char *p=lstrip(line);
    if(!*p) return 0;
    cols[n++]=p;
    while(*p && n<maxcols){
        if(p[0]==' ' && p[1]==' '){
            *p=0;
            while(*p==0 || *p==' ') p++;
            if(!*p) break;
            cols[n++]=p;
            continue;
        }
        p++;
    }
    return n;
}

static void parse_text(const char *text, Parsed *p){
    parsed_init(p);
    enum { SEC_NONE, SEC_STARTUP, SEC_DOWN, SEC_UP } sec=SEC_NONE;

    char *copy=strdup(text?text:"");
    if(!copy) return;

    char *saveptr=NULL;
    for(char *line=strtok_r(copy,"\n",&saveptr); line; line=strtok_r(NULL,"\n",&saveptr)){
        rstrip(line);
        char *s=lstrip(line);
        if(!*s) continue;

        if(strstr(s,"Startup Procedure")){ sec=SEC_STARTUP; continue; }
        if(strstr(s,"Downstream Bonded Channels")){ sec=SEC_DOWN; continue; }
        if(strstr(s,"Upstream Bonded Channels")){ sec=SEC_UP; continue; }
        if(starts_with(s,"References")){ sec=SEC_NONE; continue; }

        if(starts_with(s,"Current System Time:")){
            scpy(p->current_system_time, sizeof(p->current_system_time), s+strlen("Current System Time:"));
            trim_inplace(p->current_system_time);
            continue;
        }

        if(sec==SEC_STARTUP){
            if(starts_with(s,"Procedure") && strstr(s,"Status")) continue;
            char tmp[512]; scpy(tmp,sizeof(tmp),s);
            char *cols[4]={0};
            int n=split_cols_2spaces(tmp,cols,4);
            if(n>=2 && p->startup_n < 32){
                StartupRow *r=&p->startup[p->startup_n++];
                scpy(r->procedure,sizeof(r->procedure),cols[0]);
                scpy(r->status,sizeof(r->status),cols[1]);
                if(n>=3) scpy(r->comment,sizeof(r->comment),cols[2]);

                if(strcmp(r->procedure,"Connectivity State")==0){
                    scpy(p->connectivity_state_status,sizeof(p->connectivity_state_status),r->status);
                    scpy(p->connectivity_state_comment,sizeof(p->connectivity_state_comment),r->comment);
                }
            }
            continue;
        }

        if(sec==SEC_DOWN){
            if(!isdigit((unsigned char)s[0])) continue;
            char tmp[512]; scpy(tmp,sizeof(tmp),s);
            char *tok[32]={0}; int tn=0;
            char *sp=NULL;
            for(char *t=strtok_r(tmp," \t",&sp); t && tn<32; t=strtok_r(NULL," \t",&sp)) tok[tn++]=t;

            // expects: id Locked QAM256 393000000 Hz 1.2 dBmV 38.7 dB 0 0
            if(tn>=11 && p->down_n < 96){
                DownRow *r=&p->down[p->down_n++];
                r->channel_id = (int)parse_ll_token(tok[0]);
                scpy(r->lock_status,sizeof(r->lock_status),tok[1]);
                scpy(r->modulation,sizeof(r->modulation),tok[2]);
                r->freq_hz = parse_hz_token(tok[3]);
                r->power_dbmv = parse_double_token(tok[5]);
                r->snr_db = parse_double_token(tok[7]);
                r->corrected = parse_ll_token(tok[9]);
                r->uncorrectables = parse_ll_token(tok[10]);
            }
            continue;
        }

        if(sec==SEC_UP){
            if(!isdigit((unsigned char)s[0])) continue;
            char tmp[512]; scpy(tmp,sizeof(tmp),s);
            char *tok[32]={0}; int tn=0;
            char *sp=NULL;
            for(char *t=strtok_r(tmp," \t",&sp); t && tn<32; t=strtok_r(NULL," \t",&sp)) tok[tn++]=t;

            // expects: Channel ChannelID Locked SC-QAM 10400000 Hz 3200000 Hz 35.0 dBmV
            if(tn>=10 && p->up_n < 32){
                UpRow *r=&p->up[p->up_n++];
                r->channel = (int)parse_ll_token(tok[0]);
                r->channel_id = (int)parse_ll_token(tok[1]);
                scpy(r->lock_status,sizeof(r->lock_status),tok[2]);
                scpy(r->us_type,sizeof(r->us_type),tok[3]);
                r->freq_hz = parse_hz_token(tok[4]);
                r->width_hz = parse_hz_token(tok[6]);
                r->power_dbmv = parse_double_token(tok[8]);
            }
            continue;
        }
    }

    free(copy);
}

/* ---------------- MQTT + HA Discovery ---------------- */

static void json_escape_to(FILE *f, const char *s){
    for(const unsigned char *p=(const unsigned char*)s; *p; p++){
        unsigned char c=*p;
        switch(c){
            case '\\': fputs("\\\\",f); break;
            case '"':  fputs("\\\"",f); break;
            case '\b': fputs("\\b",f); break;
            case '\f': fputs("\\f",f); break;
            case '\n': fputs("\\n",f); break;
            case '\r': fputs("\\r",f); break;
            case '\t': fputs("\\t",f); break;
            default:
                if(c<0x20) fprintf(f,"\\u%04x",c);
                else fputc(c,f);
        }
    }
}

static int mqtt_pub(struct mosquitto *m, const char *topic, const char *payload, int qos, bool retain, FILE *lf){
    if(!m || !topic || !payload) return -1;
    int rc = mosquitto_publish(m, NULL, topic, (int)strlen(payload), payload, qos, retain);
    if(rc != MOSQ_ERR_SUCCESS){
        log_msg(lf,"MQTT publish failed topic=%s rc=%d (%s)", topic, rc, mosquitto_strerror(rc));
        return -1;
    }
    return 0;
}

static void publish_state_kv(struct mosquitto *m, const Config *cfg,
                             const char *key, const char *value, FILE *lf)
{
    char topic[512];
    snprintf(topic,sizeof(topic),"%s/%s", cfg->base_topic, key);
    mqtt_pub(m, topic, value, cfg->mqtt_qos, cfg->mqtt_retain_state, lf);
}

static void publish_state_num(struct mosquitto *m, const Config *cfg,
                              const char *key, double val, FILE *lf)
{
    char buf[64];
    snprintf(buf,sizeof(buf),"%.3f", val);
    publish_state_kv(m, cfg, key, buf, lf);
}

static void publish_state_ll(struct mosquitto *m, const Config *cfg,
                             const char *key, long long val, FILE *lf)
{
    char buf[64];
    snprintf(buf,sizeof(buf),"%lld", val);
    publish_state_kv(m, cfg, key, buf, lf);
}

static void publish_discovery_sensor(struct mosquitto *m, const Config *cfg,
                                     const char *object_id, const char *name,
                                     const char *state_topic, const char *unit,
                                     const char *device_class, const char *icon,
                                     FILE *lf)
{
    char disc_topic[512];
    snprintf(disc_topic,sizeof(disc_topic),"%s/sensor/%s/%s/config",
             cfg->ha_prefix, cfg->device_id, object_id);

    char avail_topic[512];
    snprintf(avail_topic,sizeof(avail_topic),"%s/availability", cfg->base_topic);

    char payload[2048];
    memset(payload, 0, sizeof(payload));
    FILE *mem = fmemopen(payload, sizeof(payload), "w");
    if(!mem) return;

    fprintf(mem, "{");
    fprintf(mem, "\"name\":\""); json_escape_to(mem, name); fprintf(mem, "\",");
    fprintf(mem, "\"unique_id\":\"%s_%s\",", cfg->device_id, object_id);
    fprintf(mem, "\"state_topic\":\""); json_escape_to(mem, state_topic); fprintf(mem, "\",");

    if(unit && *unit){
        fprintf(mem, "\"unit_of_measurement\":\""); json_escape_to(mem, unit); fprintf(mem, "\",");
    }
    if(device_class && *device_class){
        fprintf(mem, "\"device_class\":\""); json_escape_to(mem, device_class); fprintf(mem, "\",");
    }
    if(icon && *icon){
        fprintf(mem, "\"icon\":\""); json_escape_to(mem, icon); fprintf(mem, "\",");
    }

    fprintf(mem, "\"availability_topic\":\""); json_escape_to(mem, avail_topic); fprintf(mem, "\",");
    fprintf(mem, "\"payload_available\":\"online\",");
    fprintf(mem, "\"payload_not_available\":\"offline\",");

    fprintf(mem, "\"device\":{");
    fprintf(mem, "\"identifiers\":[\""); json_escape_to(mem, cfg->device_id); fprintf(mem, "\"],");
    fprintf(mem, "\"name\":\""); json_escape_to(mem, cfg->device_name); fprintf(mem, "\",");
    fprintf(mem, "\"manufacturer\":\"Arris\",");
    fprintf(mem, "\"model\":\"SB8200\"");
    fprintf(mem, "}");

    fprintf(mem, "}");
    fflush(mem);
    fclose(mem);

    mqtt_pub(m, disc_topic, payload, cfg->mqtt_qos, true, lf);
}

static void publish_discovery_bundle(struct mosquitto *m, const Config *cfg,
                                     const Parsed *p, FILE *lf)
{
    {
        char st[512];
        snprintf(st,sizeof(st),"%s/connectivity_state", cfg->base_topic);
        publish_discovery_sensor(m,cfg,"connectivity_state","Connectivity State", st,
                                 NULL, NULL, "mdi:check-network-outline", lf);
    }
    {
        char st[512];
        snprintf(st,sizeof(st),"%s/downstream_corrected_total", cfg->base_topic);
        publish_discovery_sensor(m,cfg,"downstream_corrected_total","Downstream Corrected (Total)", st,
                                 NULL, NULL, "mdi:counter", lf);
    }
    {
        char st[512];
        snprintf(st,sizeof(st),"%s/downstream_uncorrectables_total", cfg->base_topic);
        publish_discovery_sensor(m,cfg,"downstream_uncorrectables_total","Downstream Uncorrectables (Total)", st,
                                 NULL, NULL, "mdi:alert-circle-outline", lf);
    }

    /* -------- Downstream per Channel ID -------- */
    for(int i=0;i<p->down_n;i++){
        const DownRow *r=&p->down[i];
        if(!id_in_list(r->channel_id, cfg->down_ids, cfg->down_n)) continue;

        char obj[128], name[256], st[512];

        // lock_status (string)
        snprintf(obj,sizeof(obj),"ds_%d_lock", r->channel_id);
        snprintf(name,sizeof(name),"Downstream %d Lock Status", r->channel_id);
        snprintf(st,sizeof(st),"%s/ds/%d/lock_status", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,NULL,NULL,"mdi:lock-check-outline",lf);

        // modulation (string)
        snprintf(obj,sizeof(obj),"ds_%d_mod", r->channel_id);
        snprintf(name,sizeof(name),"Downstream %d Modulation", r->channel_id);
        snprintf(st,sizeof(st),"%s/ds/%d/modulation", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,NULL,NULL,"mdi:radio-tower",lf);

        // frequency_hz
        snprintf(obj,sizeof(obj),"ds_%d_freq", r->channel_id);
        snprintf(name,sizeof(name),"Downstream %d Frequency", r->channel_id);
        snprintf(st,sizeof(st),"%s/ds/%d/frequency_hz", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,"Hz",NULL,"mdi:sine-wave",lf);

        // power_dbmv
        snprintf(obj,sizeof(obj),"ds_%d_power", r->channel_id);
        snprintf(name,sizeof(name),"Downstream %d Power", r->channel_id);
        snprintf(st,sizeof(st),"%s/ds/%d/power_dbmv", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,"dBmV",NULL,"mdi:signal",lf);

        // snr_db
        snprintf(obj,sizeof(obj),"ds_%d_snr", r->channel_id);
        snprintf(name,sizeof(name),"Downstream %d SNR", r->channel_id);
        snprintf(st,sizeof(st),"%s/ds/%d/snr_db", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,"dB",NULL,"mdi:signal-distance-variant",lf);

        // corrected
        snprintf(obj,sizeof(obj),"ds_%d_corrected", r->channel_id);
        snprintf(name,sizeof(name),"Downstream %d Corrected", r->channel_id);
        snprintf(st,sizeof(st),"%s/ds/%d/corrected", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,NULL,NULL,"mdi:counter",lf);

        // uncorrectables
        snprintf(obj,sizeof(obj),"ds_%d_uncorrectables", r->channel_id);
        snprintf(name,sizeof(name),"Downstream %d Uncorrectables", r->channel_id);
        snprintf(st,sizeof(st),"%s/ds/%d/uncorrectables", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,NULL,NULL,"mdi:alert-circle-outline",lf);
    }

    /* -------- Upstream per Channel ID -------- */
    for(int i=0;i<p->up_n;i++){
        const UpRow *r=&p->up[i];
        if(!id_in_list(r->channel_id, cfg->up_ids, cfg->up_n)) continue;

        char obj[128], name[256], st[512];

        // channel number (the "Channel" column)
        snprintf(obj,sizeof(obj),"us_%d_channel", r->channel_id);
        snprintf(name,sizeof(name),"Upstream %d Channel", r->channel_id);
        snprintf(st,sizeof(st),"%s/us/%d/channel", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,NULL,NULL,"mdi:numeric",lf);

        // lock_status (string)
        snprintf(obj,sizeof(obj),"us_%d_lock", r->channel_id);
        snprintf(name,sizeof(name),"Upstream %d Lock Status", r->channel_id);
        snprintf(st,sizeof(st),"%s/us/%d/lock_status", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,NULL,NULL,"mdi:lock-check-outline",lf);

        // type (string)
        snprintf(obj,sizeof(obj),"us_%d_type", r->channel_id);
        snprintf(name,sizeof(name),"Upstream %d Type", r->channel_id);
        snprintf(st,sizeof(st),"%s/us/%d/type", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,NULL,NULL,"mdi:swap-vertical-bold",lf);

        // frequency_hz
        snprintf(obj,sizeof(obj),"us_%d_freq", r->channel_id);
        snprintf(name,sizeof(name),"Upstream %d Frequency", r->channel_id);
        snprintf(st,sizeof(st),"%s/us/%d/frequency_hz", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,"Hz",NULL,"mdi:sine-wave",lf);

        // width_hz
        snprintf(obj,sizeof(obj),"us_%d_width", r->channel_id);
        snprintf(name,sizeof(name),"Upstream %d Width", r->channel_id);
        snprintf(st,sizeof(st),"%s/us/%d/width_hz", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,"Hz",NULL,"mdi:arrow-expand-horizontal",lf);

        // power_dbmv
        snprintf(obj,sizeof(obj),"us_%d_power", r->channel_id);
        snprintf(name,sizeof(name),"Upstream %d Power", r->channel_id);
        snprintf(st,sizeof(st),"%s/us/%d/power_dbmv", cfg->base_topic, r->channel_id);
        publish_discovery_sensor(m,cfg,obj,name,st,"dBmV",NULL,"mdi:upload-network-outline",lf);
    }
}

/* ---------------- MQTT client lifecycle ---------------- */

typedef struct {
    struct mosquitto *mosq;
    char avail_topic[512];
} MqttCtx;

static void mqtt_ctx_init(MqttCtx *ctx){
    memset(ctx,0,sizeof(*ctx));
}

static void mqtt_ctx_destroy(MqttCtx *ctx, FILE *lf){
    (void)lf;
    if(!ctx) return;
    if(ctx->mosq){
        mosquitto_loop_stop(ctx->mosq, true);
        mosquitto_destroy(ctx->mosq);
        ctx->mosq = NULL;
    }
}

static int mqtt_ctx_start(MqttCtx *ctx, const Config *cfg, FILE *lf){
    mqtt_ctx_destroy(ctx, lf);
    g_mqtt_up = 0;

    ctx->mosq = mosquitto_new(cfg->mqtt_client_id, true, NULL);
    if(!ctx->mosq){
        log_msg(lf,"mosquitto_new failed");
        return -1;
    }

    mosquitto_connect_callback_set(ctx->mosq, on_mqtt_connect);
    mosquitto_disconnect_callback_set(ctx->mosq, on_mqtt_disconnect);
    mosquitto_reconnect_delay_set(ctx->mosq, 1, 30, true);

    if(cfg->mqtt_user[0]){
        mosquitto_username_pw_set(ctx->mosq, cfg->mqtt_user, cfg->mqtt_pass[0] ? cfg->mqtt_pass : NULL);
    }

    snprintf(ctx->avail_topic,sizeof(ctx->avail_topic),"%s/availability", cfg->base_topic);
    mosquitto_will_set(ctx->mosq, ctx->avail_topic, 7, "offline", cfg->mqtt_qos, true);

    int rc = mosquitto_connect(ctx->mosq, cfg->mqtt_host, cfg->mqtt_port, 30);
    if(rc != MOSQ_ERR_SUCCESS){
        log_msg(lf,"mosquitto_connect failed: %s (will retry)", mosquitto_strerror(rc));
    }

    mosquitto_loop_start(ctx->mosq);
    return 0;
}

/* ---------------- config comparison / reload ---------------- */

static bool mqtt_settings_changed(const Config *a, const Config *b){
    if(!files_equal_str(a->mqtt_host,b->mqtt_host)) return true;
    if(a->mqtt_port != b->mqtt_port) return true;
    if(!files_equal_str(a->mqtt_user,b->mqtt_user)) return true;
    if(!files_equal_str(a->mqtt_pass,b->mqtt_pass)) return true;
    if(!files_equal_str(a->mqtt_client_id,b->mqtt_client_id)) return true;
    if(a->mqtt_qos != b->mqtt_qos) return true;
    return false;
}

static bool discovery_related_changed(const Config *a, const Config *b){
    if(!files_equal_str(a->ha_prefix,b->ha_prefix)) return true;
    if(!files_equal_str(a->device_name,b->device_name)) return true;
    if(!files_equal_str(a->device_id,b->device_id)) return true;
    if(!files_equal_str(a->base_topic,b->base_topic)) return true;
    if(!int_lists_equal(a->down_ids,a->down_n,b->down_ids,b->down_n)) return true;
    if(!int_lists_equal(a->up_ids,a->up_n,b->up_ids,b->up_n)) return true;
    return false;
}

static bool log_path_changed(const Config *a, const Config *b){
    return !files_equal_str(a->log_path, b->log_path);
}

/* ---------------- main ---------------- */

static void usage(const char *p){
    fprintf(stderr,"Usage: %s [--ini /etc/sb2mqtt.ini]\n", p);
}

int main(int argc, char **argv){
    // Re-publish HA discovery every 30 minutes (retained config topics)
    const int DISCOVERY_REPUBLISH_SEC = 1800;

    const char *ini_path = "/etc/sb2mqtt.ini";
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"--ini")==0 && i+1<argc) ini_path = argv[++i];
        else if(strcmp(argv[i],"-h")==0 || strcmp(argv[i],"--help")==0){ usage(argv[0]); return 0; }
        else { usage(argv[0]); return 2; }
    }

    signal(SIGINT,on_sig);
    signal(SIGTERM,on_sig);

    Config cfg; cfg_defaults(&cfg);

    make_dirs_for_file(cfg.log_path);
    FILE *lf = fopen(cfg.log_path,"a");
    if(!lf) lf = stderr;

    cfg_load_ini(&cfg, ini_path, lf);

    if(lf != stderr) fclose(lf);
    make_dirs_for_file(cfg.log_path);
    lf = fopen(cfg.log_path,"a");
    if(!lf) lf = stderr;

    log_msg(lf,"starting: ini=%s url=%s interval=%d timeout=%d mqtt=%s:%d base_topic=%s device_id=%s",
            ini_path, cfg.url, cfg.interval_sec, cfg.timeout_sec,
            cfg.mqtt_host, cfg.mqtt_port, cfg.base_topic, cfg.device_id);

    mosquitto_lib_init();

    MqttCtx mctx; mqtt_ctx_init(&mctx);
    mqtt_ctx_start(&mctx, &cfg, lf);

    bool discovery_sent = false;
    time_t last_discovery_publish = 0;

    time_t last_ini_check = 0;
    time_t last_ini_mtime = 0;
    {
        struct stat st;
        if(stat(ini_path, &st)==0) last_ini_mtime = st.st_mtime;
    }

    int time_to_poll = 0;

    while(!g_stop){
        time_t now = time(NULL);

        // Force rediscovery every 30 minutes (publish on next successful poll)
        if(DISCOVERY_REPUBLISH_SEC > 0 && last_discovery_publish > 0){
            if((int)(now - last_discovery_publish) >= DISCOVERY_REPUBLISH_SEC){
                discovery_sent = false;
            }
        }

        // INI reload checks (mtime)
        if(now - last_ini_check >= cfg.ini_check_sec){
            last_ini_check = now;

            struct stat st;
            if(stat(ini_path, &st)==0){
                if(st.st_mtime != last_ini_mtime){
                    last_ini_mtime = st.st_mtime;

                    Config newcfg;
                    cfg_defaults(&newcfg);
                    cfg_load_ini(&newcfg, ini_path, lf);

                    bool need_mqtt_reconnect = mqtt_settings_changed(&cfg, &newcfg);
                    bool need_discovery      = discovery_related_changed(&cfg, &newcfg);
                    bool need_log_reopen     = log_path_changed(&cfg, &newcfg);

                    if(need_log_reopen){
                        log_msg(lf,"log path changed -> %s", newcfg.log_path);
                        if(lf != stderr) fclose(lf);
                        make_dirs_for_file(newcfg.log_path);
                        lf = fopen(newcfg.log_path,"a");
                        if(!lf) lf = stderr;
                    }

                    if((need_mqtt_reconnect || need_discovery) && g_mqtt_up && mctx.mosq && mctx.avail_topic[0]){
                        mqtt_pub(mctx.mosq, mctx.avail_topic, "offline", cfg.mqtt_qos, true, lf);
                    }

                    cfg = newcfg;

                    if(need_mqtt_reconnect || need_discovery){
                        log_msg(lf,"INI changed -> reconnect MQTT and republish discovery next poll");
                        mqtt_ctx_start(&mctx, &cfg, lf);
                        discovery_sent = false;
                        last_discovery_publish = 0;
                    } else {
                        log_msg(lf,"INI changed -> no MQTT reconnect needed");
                    }

                    time_to_poll = 0; // poll immediately after reload
                }
            }
        }

        if(!g_mqtt_up && mctx.mosq){
            mosquitto_reconnect(mctx.mosq);
        }

        if(time_to_poll <= 0){
            char *raw=NULL; size_t rawlen=0;

            int ok = run_lynx_capture(cfg.url, cfg.timeout_sec, &raw, &rawlen, lf);
            if(ok==0 && raw && rawlen>0){
                Parsed p; parse_text(raw, &p);

                if(g_mqtt_up && mctx.mosq){
                    mqtt_pub(mctx.mosq, mctx.avail_topic, "online", cfg.mqtt_qos, true, lf);

                    if(!discovery_sent){
                        publish_discovery_bundle(mctx.mosq, &cfg, &p, lf);
                        discovery_sent = true;
                        last_discovery_publish = time(NULL);
                        log_msg(lf,"HA discovery published");
                    }

                    publish_state_kv(mctx.mosq, &cfg, "connectivity_state",
                                     p.connectivity_state_status[0] ? p.connectivity_state_status : "unknown", lf);

                    long long ds_corr_total=0, ds_unc_total=0;

                    for(int i=0;i<p.down_n;i++){
                        const DownRow *r=&p.down[i];
                        ds_corr_total += r->corrected;
                        ds_unc_total  += r->uncorrectables;

                        if(!id_in_list(r->channel_id, cfg.down_ids, cfg.down_n)) continue;

                        char key[256];

                        // Full downstream row fields
                        snprintf(key,sizeof(key),"ds/%d/lock_status", r->channel_id);
                        publish_state_kv(mctx.mosq,&cfg,key,r->lock_status[0]?r->lock_status:"",lf);

                        snprintf(key,sizeof(key),"ds/%d/modulation", r->channel_id);
                        publish_state_kv(mctx.mosq,&cfg,key,r->modulation[0]?r->modulation:"",lf);

                        snprintf(key,sizeof(key),"ds/%d/frequency_hz", r->channel_id);
                        publish_state_ll(mctx.mosq,&cfg,key,(long long)r->freq_hz,lf);

                        snprintf(key,sizeof(key),"ds/%d/power_dbmv", r->channel_id);
                        publish_state_num(mctx.mosq,&cfg,key,r->power_dbmv,lf);

                        snprintf(key,sizeof(key),"ds/%d/snr_db", r->channel_id);
                        publish_state_num(mctx.mosq,&cfg,key,r->snr_db,lf);

                        snprintf(key,sizeof(key),"ds/%d/corrected", r->channel_id);
                        publish_state_ll(mctx.mosq,&cfg,key,r->corrected,lf);

                        snprintf(key,sizeof(key),"ds/%d/uncorrectables", r->channel_id);
                        publish_state_ll(mctx.mosq,&cfg,key,r->uncorrectables,lf);
                    }

                    publish_state_ll(mctx.mosq,&cfg,"downstream_corrected_total", ds_corr_total, lf);
                    publish_state_ll(mctx.mosq,&cfg,"downstream_uncorrectables_total", ds_unc_total, lf);

                    for(int i=0;i<p.up_n;i++){
                        const UpRow *r=&p.up[i];
                        if(!id_in_list(r->channel_id, cfg.up_ids, cfg.up_n)) continue;

                        char key[256];

                        // Full upstream row fields
                        snprintf(key,sizeof(key),"us/%d/channel", r->channel_id);
                        publish_state_ll(mctx.mosq,&cfg,key,(long long)r->channel,lf);

                        snprintf(key,sizeof(key),"us/%d/lock_status", r->channel_id);
                        publish_state_kv(mctx.mosq,&cfg,key,r->lock_status[0]?r->lock_status:"",lf);

                        snprintf(key,sizeof(key),"us/%d/type", r->channel_id);
                        publish_state_kv(mctx.mosq,&cfg,key,r->us_type[0]?r->us_type:"",lf);

                        snprintf(key,sizeof(key),"us/%d/frequency_hz", r->channel_id);
                        publish_state_ll(mctx.mosq,&cfg,key,(long long)r->freq_hz,lf);

                        snprintf(key,sizeof(key),"us/%d/width_hz", r->channel_id);
                        publish_state_ll(mctx.mosq,&cfg,key,(long long)r->width_hz,lf);

                        snprintf(key,sizeof(key),"us/%d/power_dbmv", r->channel_id);
                        publish_state_num(mctx.mosq,&cfg,key,r->power_dbmv,lf);
                    }
                }

                log_msg(lf,"poll ok: ds=%d us=%d connectivity=%s mqtt=%s",
                        p.down_n, p.up_n,
                        p.connectivity_state_status[0]?p.connectivity_state_status:"unknown",
                        g_mqtt_up ? "up" : "down");
            } else {
                log_msg(lf,"poll failed (no output?)");
                if(g_mqtt_up && mctx.mosq){
                    publish_state_kv(mctx.mosq,&cfg,"connectivity_state","unknown",lf);
                }
            }

            free(raw);
            time_to_poll = cfg.interval_sec;
        }

        sleep(1);
        time_to_poll--;
    }

    if(g_mqtt_up && mctx.mosq && mctx.avail_topic[0]){
        mqtt_pub(mctx.mosq, mctx.avail_topic, "offline", cfg.mqtt_qos, true, lf);
    }

    mqtt_ctx_destroy(&mctx, lf);
    mosquitto_lib_cleanup();

    log_msg(lf,"stopping");
    if(lf && lf!=stderr) fclose(lf);
    return 0;
}
