/* Test-only interposition around real kernel operations. Never linked into
 * production. Configuration is cached before any clone; the child path only
 * uses inherited POD storage and raw syscalls. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

static long (*real_call)(long,...);
static char mode[64],arm[4096];
static int entered,release_fd,active;
__attribute__((constructor)) static void initialize(void) {
    real_call=dlsym(RTLD_NEXT,"syscall");
    const char *p=getenv("SIGRUND_EXEC_MODE"),*a=getenv("SIGRUND_EXEC_ARM");
    if(p)snprintf(mode,sizeof(mode),"%s",p);
    if(a)snprintf(arm,sizeof(arm),"%s",a);
    p=getenv("SIGRUND_EXEC_ENTERED");entered=p?atoi(p):-1;
    p=getenv("SIGRUND_EXEC_RELEASE");release_fd=p?atoi(p):-1;
}
static int take_arm(void) {return arm[0]&&real_call(SYS_unlinkat,AT_FDCWD,arm,0)==0;}
static void gate(long pid) {
    uint64_t message[2]={(uint64_t)real_call(SYS_gettid),(uint64_t)pid};
    long n;
    do{n=real_call(SYS_write,entered,message,sizeof(message));}while(n<0&&errno==EINTR);
    char byte;
    do{n=real_call(SYS_read,release_fd,&byte,1);}while(n<0&&errno==EINTR);
}
long syscall(long number,...) {
    va_list ap;va_start(ap,number);
    long args[6];for(unsigned i=0;i<6;++i)args[i]=va_arg(ap,long);va_end(ap);
    if(number==SYS_clone3) {
        if(!strcmp(mode,"clone-fail")&&take_arm()){errno=ENOSYS;return -1;}
        long result=real_call(number,args[0],args[1],args[2],args[3],args[4],args[5]);
        int saved=errno;
        if(result>0&&!strcmp(mode,"clone-after")&&take_arm())gate(result);
        if(result==0&&strcmp(mode,"clone-after"))active=take_arm();
        errno=saved;return result;
    }
    if(active) {
        if(number==SYS_unshare&&!strcmp(mode,"fd-exhaust")) {
            const struct rlimit limit={128,128};
            if(real_call(SYS_setrlimit,RLIMIT_NOFILE,&limit)<0)real_call(SYS_exit_group,98);
            while(real_call(SYS_openat,AT_FDCWD,"/dev/null",O_RDONLY|O_CLOEXEC,0)>=0){}
        }
        if(number==SYS_mount_setattr&&!strcmp(mode,"mount-unavailable")){errno=ENOSYS;return -1;}
        unsigned step=0;
        if(number==SYS_unshare)step=1;
        if(number==SYS_chdir)step=2;
        if(number==SYS_prctl&&args[0]==PR_CAPBSET_DROP)step=3;
        if(number==SYS_prctl&&args[0]==PR_SET_SECUREBITS)step=4;
        if(number==SYS_setgroups)step=5;
        if(number==SYS_setresuid)step=6;
        if(number==SYS_capset)step=7;
        if(number==SYS_prctl&&args[0]==PR_CAP_AMBIENT&&args[1]==PR_CAP_AMBIENT_CLEAR_ALL)step=8;
        if(number==SYS_prctl&&args[0]==PR_SET_NO_NEW_PRIVS)step=9;
        if(number==SYS_capget)step=10;
        if(number==SYS_execveat)step=11;
        if(step&&!strncmp(mode,"step-",5)&&(unsigned)atoi(mode+5)==step){errno=EIO;return -1;}
        if(number==SYS_write&&args[0]==4&&args[2]==8) {
            const uint32_t *frame=(void *)args[1];
            if(frame[0]==0&&frame[1]==0) {
                if(!strcmp(mode,"kill-before-ready"))real_call(SYS_kill,real_call(SYS_getpid),SIGKILL);
                if(!strcmp(mode,"stop-before-ready"))real_call(SYS_kill,real_call(SYS_getpid),SIGSTOP);
                if(!strcmp(mode,"partial-ready")) {
                    real_call(SYS_write,4,frame,3);
                    real_call(SYS_exit_group,127);
                }
                if(!strcmp(mode,"excess-ready")) {
                    const char excess[17]={0};
                    real_call(SYS_write,4,excess,sizeof(excess));
                    real_call(SYS_exit_group,127);
                }
                if(!strcmp(mode,"stop-after-ready")) {
                    long n=real_call(number,args[0],args[1],args[2],args[3],args[4],args[5]);
                    real_call(SYS_kill,real_call(SYS_getpid),SIGSTOP);
                    return n;
                }
            }
        }
        if(number==SYS_execveat&&!strcmp(mode,"kill-after-ready"))real_call(SYS_kill,real_call(SYS_getpid),SIGKILL);
    }
    return real_call(number,args[0],args[1],args[2],args[3],args[4],args[5]);
}
int openat(int dir,const char *path,int flags,...) {
    mode_t permissions=0;
    if(flags&O_CREAT){va_list ap;va_start(ap,flags);permissions=va_arg(ap,int);va_end(ap);}
    if(!strcmp(mode,"swap-unavailable")&&!strcmp(path,"memory.swap.max")){errno=ENOENT;return -1;}
    return real_call(SYS_openat,dir,path,flags,permissions);
}
ssize_t write(int fd,const void *data,size_t len) {
    if(!strcmp(mode,"cleanup-before")||!strcmp(mode,"cleanup-fail")) {
        char name[64],path[4096];snprintf(name,sizeof(name),"/proc/self/fd/%d",fd);
        long n=real_call(SYS_readlink,name,path,sizeof(path)-1);
        if(n>0){path[n]=0;size_t size=strlen(path);const char *tail="/cgroup.kill";
            if(size>=strlen(tail)&&!strcmp(path+size-strlen(tail),tail)&&take_arm()) {
                if(!strcmp(mode,"cleanup-fail")){errno=EIO;return -1;}
                gate(0);
            }}
    }
    return real_call(SYS_write,fd,data,len);
}
