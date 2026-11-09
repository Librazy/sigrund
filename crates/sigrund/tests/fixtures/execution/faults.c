/* Test-only interposition around real kernel operations. Never linked into
 * production. Configuration is cached before any clone; the child path only
 * uses inherited POD storage and raw syscalls. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static long (*real_call)(long,...);
static char mode[64],arm[4096];
static int entered,release_fd,active;
static int partial_decision_fd = -1;
static char preload_env[8192],mode_env[128],arm_env[8192];
static char *launcher_env[] = {preload_env, mode_env, arm_env, "SIGRUND_EXEC_LAUNCHER=1", NULL};
__attribute__((constructor)) static void initialize(void) {
    real_call=dlsym(RTLD_NEXT,"syscall");
    const char *p=getenv("SIGRUND_EXEC_MODE"),*a=getenv("SIGRUND_EXEC_ARM");
    if(p)snprintf(mode,sizeof(mode),"%s",p);
    if(a)snprintf(arm,sizeof(arm),"%s",a);
    p=getenv("LD_PRELOAD");
    if(p)snprintf(preload_env,sizeof(preload_env),"LD_PRELOAD=%s",p);
    snprintf(mode_env,sizeof(mode_env),"SIGRUND_EXEC_MODE=%s",mode);
    snprintf(arm_env,sizeof(arm_env),"SIGRUND_EXEC_ARM=%s",arm);
    if(getenv("SIGRUND_EXEC_LAUNCHER"))active=1;
    p=getenv("SIGRUND_EXEC_ENTERED");entered=p?atoi(p):-1;
    p=getenv("SIGRUND_EXEC_RELEASE");release_fd=p?atoi(p):-1;
    if(active&&!strcmp(mode,"namespace-bootstrap-memory")) {
        char path[8192],pid[32];
        snprintf(path,sizeof(path),"%s.entered",arm);
        int fd=real_call(SYS_openat,AT_FDCWD,path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
        int length=snprintf(pid,sizeof(pid),"%ld",real_call(SYS_getpid));
        if(fd<0||real_call(SYS_write,fd,pid,length)!=length)real_call(SYS_exit_group,99);
        real_call(SYS_close,fd);
        snprintf(path,sizeof(path),"%s.release",arm);
        struct timespec pause={.tv_nsec=1000000};
        unsigned retry;
        for(retry=0;retry<1500;++retry) {
            fd=real_call(SYS_openat,AT_FDCWD,path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW,0);
            if(fd>=0){real_call(SYS_close,fd);break;}
            real_call(SYS_nanosleep,&pause,NULL);
        }
        if(retry==1500)real_call(SYS_exit_group,99);
    }
}
static int take_arm(void) {return arm[0]&&real_call(SYS_unlinkat,AT_FDCWD,arm,0)==0;}
static int parent_gate_mode(void) {
    return !strcmp(mode,"cleanup-before") || !strcmp(mode,"cleanup-fail") ||
           !strcmp(mode,"prepare-before") || !strcmp(mode,"limit-fail");
}
static void gate(long pid) {
    uint64_t message[2]={(uint64_t)real_call(SYS_gettid),(uint64_t)pid};
    long n;
    do{n=real_call(SYS_write,entered,message,sizeof(message));}while(n<0&&errno==EINTR);
    char byte;
    do{n=real_call(SYS_read,release_fd,&byte,1);}while(n<0&&errno==EINTR);
}
/* Hold the real coordinator immediately before detach, after exec validation.
 * This is test-only: killing it must trigger EXITKILL before target entry. */
long ptrace(enum __ptrace_request request, ...) {
    va_list ap;va_start(ap,request);
    pid_t pid=va_arg(ap,pid_t);
    void *address=va_arg(ap,void *),*data=va_arg(ap,void *);
    va_end(ap);
    if(request==PTRACE_DETACH&&!strcmp(mode,"exec-detach")&&take_arm())gate(pid);
    return real_call(SYS_ptrace,request,pid,address,data);
}
long syscall(long number,...) {
    va_list ap;va_start(ap,number);
    long args[6];for(unsigned i=0;i<6;++i)args[i]=va_arg(ap,long);va_end(ap);
    /* Reinject ONLY this root-owned test interposer across the new bootstrap
     * exec. Production supplies an empty environment and no fault controls. */
    if(number==SYS_execve&&!strcmp((const char *)args[0],"/proc/self/exe"))
        return real_call(number,args[0],args[1],launcher_env,args[3],args[4],args[5]);
    if(number==SYS_clone3) {
        if(!strcmp(mode,"clone-fail")&&take_arm()){errno=ENOSYS;return -1;}
        if(active&&!strcmp(mode,"namespace-final-clone")&&
           !(((struct clone_args *)args[0])->flags&CLONE_INTO_CGROUP)){errno=EIO;return -1;}
        long result=real_call(number,args[0],args[1],args[2],args[3],args[4],args[5]);
        int saved=errno;
        if(result>0&&!strcmp(mode,"clone-after")&&take_arm())gate(result);
        if(result>0&&parent_gate_mode())active=1;
        if(result==0&&strcmp(mode,"clone-after")&&strcmp(mode,"exec-detach")&&!parent_gate_mode())active=active||take_arm();
        errno=saved;return result;
    }
    if(active) {
        if(number==SYS_fchdir&&args[0]==25&&!strcmp(mode,"namespace-covered-cwd"))
            return real_call(SYS_chdir,"/run");
        if((number==SYS_setns&&!strcmp(mode,"namespace-setns")) ||
           (number==SYS_chroot&&!strcmp(mode,"namespace-root")) ||
           (number==SYS_unshare&&(args[0]&CLONE_NEWNS)&&!strcmp(mode,"namespace-private")) ||
           (number==SYS_mount&&!strcmp((const char *)args[1],"/run")&&!strcmp(mode,"namespace-run"))) {
            errno=EIO;return -1;
        }
        if(number==SYS_sendmsg) {
            const struct msghdr *message=(void *)args[1];
            if(message->msg_iovlen==1&&message->msg_iov[0].iov_len==8) {
                const uint32_t *words=message->msg_iov[0].iov_base;
                if(words[0]==1&&!strcmp(mode,"namespace-ready-deadline"))
                    real_call(SYS_kill,real_call(SYS_getpid),SIGSTOP);
                if((words[0]==1&&!strcmp(mode,"namespace-short-ready")) ||
                   (words[0]==2&&!strcmp(mode,"namespace-short-handoff"))) {
                    struct iovec iov={.iov_base=message->msg_iov[0].iov_base,.iov_len=7};
                    struct msghdr shortened=*message;shortened.msg_iov=&iov;
                    return real_call(SYS_sendmsg,args[0],&shortened,args[2]);
                }
            }
        }
        if(number==SYS_write&&(args[2]==2||args[2]==8)) {
            char name[64],path[4096];
            snprintf(name,sizeof(name),"/proc/self/fd/%d",(int)args[0]);
            long n=real_call(SYS_readlinkat,AT_FDCWD,name,path,sizeof(path)-1);
            if(n>0) {
                path[n]=0;
                size_t size=strlen(path);
                const char *tail=(!strcmp(mode,"prepare-before")||!strcmp(mode,"limit-fail"))?"/pids.max":"/cgroup.kill";
                if(size>=strlen(tail)&&!strcmp(path+size-strlen(tail),tail)&&take_arm()) {
                    if(!strcmp(mode,"cleanup-fail")||!strcmp(mode,"limit-fail")){errno=EIO;return -1;}
                    gate(0);
                }
            }
        }
        if(number==SYS_unshare&&!strcmp(mode,"fd-exhaust")) {
            const struct rlimit limit={128,128};
            if(real_call(SYS_prlimit64,0,RLIMIT_NOFILE,&limit,NULL)<0)real_call(SYS_exit_group,98);
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
    if(!strcmp(mode,"cleanup-before")||!strcmp(mode,"cleanup-fail")||!strcmp(mode,"prepare-before")||!strcmp(mode,"limit-fail")) {
        char name[64],path[4096];snprintf(name,sizeof(name),"/proc/self/fd/%d",fd);
        long n=real_call(SYS_readlinkat,AT_FDCWD,name,path,sizeof(path)-1);
        if(n>0){path[n]=0;size_t size=strlen(path);const char *tail=(!strcmp(mode,"prepare-before")||!strcmp(mode,"limit-fail"))?"/pids.max":"/cgroup.kill";
            if(size>=strlen(tail)&&!strcmp(path+size-strlen(tail),tail)&&take_arm()) {
                if((!strcmp(mode,"cleanup-fail")||!strcmp(mode,"limit-fail"))){errno=EIO;return -1;}
                gate(0);
            }}
    }
    return real_call(SYS_write,fd,data,len);
}
ssize_t send(int fd,const void *data,size_t len,int flags) {
    if(!strcmp(mode,"namespace-partial-approved")) {
        if(fd==partial_decision_fd){errno=EAGAIN;return -1;}
        if(len>5&&((const unsigned char *)data)[0]==2&&memmem(data,len,"APPROVED",8)&&take_arm()) {
            partial_decision_fd=fd;
            uint64_t message[2]={(uint64_t)real_call(SYS_gettid),0};
            real_call(SYS_write,entered,message,sizeof(message));
            return real_call(SYS_sendto,fd,data,1,flags,NULL,0);
        }
    }
    return real_call(SYS_sendto,fd,data,len,flags,NULL,0);
}
