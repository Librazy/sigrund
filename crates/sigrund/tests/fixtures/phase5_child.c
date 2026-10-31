#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/memfd.h>
#include <signal.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* The production source is compiled unchanged for the library. This separate
 * test translation unit injects failures at syscall boundaries; the daemon has
 * no environment-driven fault switches. */
static int injection_index, seen;
static long failed_syscall;
static unsigned fault_seen, next_fault_occurrence=1;
static int kill_at_exec;
static int inject(long n) {
    if ((kill_at_exec==1 && n == SYS_execveat) || (kill_at_exec==2 && n==SYS_write)) { kill(getpid(),SIGKILL); _exit(99); }
    if (failed_syscall && n == failed_syscall && ++fault_seen == next_fault_occurrence) {errno=EIO;return 1;}
    if (n != SYS_unshare && n != SYS_fcntl && n != SYS_dup3 && n != SYS_close_range) return 0;
    if (++seen == injection_index) {errno=EMFILE;return 1;} return 0;
}
#define syscall(n, ...) (inject(n) ? -1L : (syscall)(n, ##__VA_ARGS__))
#include "../../src/child/setup.c"
#undef syscall

#define REQUIRE(expr) do { if (!(expr)) {fprintf(stderr,"%s:%d: %s (%s)\n",__FILE__,__LINE__,#expr,strerror(errno));exit(1);} } while (0)
static int highfd(int fd) {int n=fcntl(fd,F_DUPFD_CLOEXEC,32);REQUIRE(n>=32);close(fd);return n;}
static int executable(void) {
    int source=open("/proc/self/exe",O_RDONLY|O_CLOEXEC); REQUIRE(source>=0);
    int fd=syscall(SYS_memfd_create,"sigrund-setup-test",MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10);
    REQUIRE(fd>=0); char chunk[65536]; ssize_t n;
    while ((n=read(source,chunk,sizeof(chunk)))>0) REQUIRE(write(fd,chunk,n)==n);
    REQUIRE(n==0);close(source);REQUIRE(fchmod(fd,0111)==0);
    REQUIRE(fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL|F_SEAL_EXEC)==0);
    return highfd(fd);
}
static void wait_ok(pid_t pid, int expected) {int status;REQUIRE(waitpid(pid,&status,0)==pid);REQUIRE(WIFEXITED(status)&&WEXITSTATUS(status)==expected);}
static void test_fd_failure(int fail_at, int closed_mask, int exhaust) {
    int pipefd[2]; REQUIRE(pipe2(pipefd,O_CLOEXEC)==0);
    int r=highfd(pipefd[0]), w=highfd(pipefd[1]);
    int null=highfd(open("/dev/null",O_RDWR|O_CLOEXEC));
    char scratch[1024];
    struct child_spec spec={.input=null,.output=null,.error=null,.executable=null,.sync=w,.mountinfo=scratch,.mountinfo_capacity=sizeof(scratch)};
    int sentinel=highfd(memfd_create("sentinel",MFD_CLOEXEC));
    REQUIRE(write(sentinel,"sentinel",8)==8);
    pid_t pid=fork();REQUIRE(pid>=0);
    if (!pid) {
        close(r); REQUIRE(dup2(sentinel,4)==4);
        for (int i=0;i<5;++i) if (closed_mask&(1<<i)) close(i);
        injection_index=fail_at;seen=0;
        if(exhaust){struct rlimit limit={64,64};REQUIRE(setrlimit(RLIMIT_NOFILE,&limit)==0);while(open("/dev/null",O_RDONLY|O_CLOEXEC)>=0){} for(int i=0;i<5;++i)if(closed_mask&(1<<i))close(i);}
        run_child(&spec);
    }
    close(w);
    struct setup_frame frame; REQUIRE(read(r,&frame,8)==8);REQUIRE(frame.step==1);if(frame.error!=EMFILE)fprintf(stderr,"case fail=%d mask=%d exhaust=%d step=%u errno=%d\n",fail_at,closed_mask,exhaust,frame.step,frame.error);REQUIRE(frame.error==EMFILE);
    char extra;REQUIRE(read(r,&extra,1)==0);
    wait_ok(pid,127);
    char check[8];REQUIRE(pread(sentinel,check,8,0)==8);REQUIRE(!memcmp(check,"sentinel",8));
    close(r);close(null);close(sentinel);
}
static unsigned last_cap(void) {FILE *f=fopen("/proc/sys/kernel/cap_last_cap","r");unsigned n;REQUIRE(f&&fscanf(f,"%u",&n)==1&&n<64);fclose(f);return n;}
static void probe(void) {
    const char *uid=getenv("P5_UID"),*caps=getenv("P5_CAPS");REQUIRE(uid&&caps);
    uint32_t wanted=strtoul(uid,NULL,10);uint64_t cap=strtoull(caps,NULL,10);
    uid_t ur,ue,us;gid_t gr,ge,gs;REQUIRE(getresuid(&ur,&ue,&us)==0&&ur==wanted&&ue==wanted&&us==wanted);
    REQUIRE(getresgid(&gr,&ge,&gs)==0&&gr==wanted&&ge==wanted&&gs==wanted);
    gid_t group[2];REQUIRE(getgroups(2,group)==1&&group[0]==wanted);
    REQUIRE(prctl(PR_GET_SECUREBITS)==0x2f&&prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1);
    struct __user_cap_header_struct head={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct data[2];
    REQUIRE(syscall(SYS_capget,&head,data)==0);
    for(unsigned i=0;i<2;++i){uint32_t c=cap>>(i*32);REQUIRE(data[i].effective==c&&data[i].permitted==c&&data[i].inheritable==c);}
    for(unsigned i=0;i<=last_cap();++i){int c=!!(cap&(1ULL<<i));REQUIRE(prctl(PR_CAPBSET_READ,i,0,0,0)==c&&prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,i,0,0)==c);}
    REQUIRE(umask(0)==027);char cwd[2];REQUIRE(getcwd(cwd,sizeof(cwd))&&!strcmp(cwd,"/"));
    REQUIRE(getsid(0)==getpid());
    sigset_t mask;REQUIRE(sigprocmask(SIG_SETMASK,NULL,&mask)==0);
    for(int i=1;i<NSIG;++i)REQUIRE(sigismember(&mask,i)!=1);
    struct sigaction action;REQUIRE(sigaction(SIGPIPE,NULL,&action)==0&&action.sa_handler==SIG_DFL);
    REQUIRE(sigaction(SIGCHLD,NULL,&action)==0&&action.sa_handler==SIG_DFL);
    for(int i=0;i<3;++i) REQUIRE(fcntl(i,F_GETFD)>=0);
    for(int i=3;i<128;++i) REQUIRE(fcntl(i,F_GETFD)<0&&errno==EBADF);
    if (getenv("P5_ISOLATED")) {
        struct statvfs st;REQUIRE(statvfs("/sys/fs/cgroup",&st)==0);
        unsigned long required=ST_RDONLY|ST_NOSUID|ST_NODEV|ST_NOEXEC;
        REQUIRE((st.f_flag&required)==required);
        char *mounts=malloc(1048576);REQUIRE(mounts);
        int fd=open("/proc/self/mountinfo",O_RDONLY|O_CLOEXEC);REQUIRE(fd>=0);
        size_t count=0;
        for (;;) {
            REQUIRE(count<1048576);
            ssize_t n=read(fd,mounts+count,1048576-count);
            if(n<0&&errno==EINTR)continue;
            REQUIRE(n>=0);
            if(!n)break;
            count+=(size_t)n;
        }
        REQUIRE(count>0);
        REQUIRE(check_mountinfo(mounts,count));close(fd);free(mounts);
    }
    REQUIRE(write(1,"probe-ok\n",9)==9);
}
static void setup_test(uint32_t uid, uint64_t caps, int exec_error, long fault, unsigned step, int kill_window) {
    int p[2],o[2];REQUIRE(pipe2(p,O_CLOEXEC)==0);REQUIRE(pipe2(o,O_CLOEXEC)==0);
    int exec=executable();
    if(exec_error){close(exec);exec=highfd(open("/dev/null",O_RDONLY|O_CLOEXEC));}
    int null=highfd(open("/dev/null",O_RDWR|O_CLOEXEC));
    char *mountinfo=calloc(1,1048576);REQUIRE(mountinfo);
    uint32_t group=uid,check=~0U;char uid_env[64],caps_env[64];snprintf(uid_env,sizeof(uid_env),"P5_UID=%u",uid);snprintf(caps_env,sizeof(caps_env),"P5_CAPS=%llu",(unsigned long long)caps);
    const char *args[]={"phase5-probe","--probe",NULL},*env[]={uid_env,caps_env,NULL};
    struct child_spec spec={.input=null,.output=o[1],.error=2,.executable=exec,.sync=p[1],.uid=uid,.gid=uid,.mask=027,.last_cap=last_cap(),.capabilities=caps,.groups=&group,.groups_len=1,.group_check=&check,.cwd="/",.argv=args,.envp=env,.mountinfo=mountinfo,.mountinfo_capacity=1048576,.isolated=(fault==SYS_mount||fault==SYS_mount_setattr)};
    pid_t pid=fork();REQUIRE(pid>=0);
    if(!pid){close(p[0]);close(o[0]);if(spec.isolated)REQUIRE(unshare(CLONE_NEWNS)==0);injection_index=0;seen=0;failed_syscall=fault;fault_seen=0;kill_at_exec=kill_window;run_child(&spec);}
    close(p[1]);close(o[1]);
    unsigned char frames[17];size_t used=0;ssize_t n;
    while((n=read(p[0],frames+used,sizeof(frames)-used))>0){used+=n;REQUIRE(used<sizeof(frames));}
    REQUIRE(n==0);
    if (kill_window==2 || fault==SYS_write) {
        REQUIRE(used==0);
        int status;REQUIRE(waitpid(pid,&status,0)==pid);
        REQUIRE(kill_window? (WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL):(WIFEXITED(status)&&WEXITSTATUS(status)==127));
        char output;REQUIRE(read(o[0],&output,1)==0);
        close(p[0]);close(o[0]);close(exec);close(null);free(mountinfo);return;
    }
    struct setup_frame a,b;REQUIRE(used==(exec_error?16:8));memcpy(&a,frames,8);
    if(a.step!=step||a.error!=(fault?EIO:0))fprintf(stderr,"fault=%ld occurrence=%u expected=%u actual=%u errno=%d\n",fault,next_fault_occurrence,step,a.step,a.error);
    REQUIRE(a.step==step&&a.error==(fault?EIO:0));
    if(exec_error){memcpy(&b,frames+8,8);REQUIRE(b.step==11&&b.error>0);}
    if(kill_window){int status;REQUIRE(waitpid(pid,&status,0)==pid);REQUIRE(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);}
    else wait_ok(pid,(exec_error||fault)?127:0);
    char output[32];n=read(o[0],output,sizeof(output));REQUIRE((exec_error||fault||kill_window)?n==0:(n==9&&!memcmp(output,"probe-ok\n",9)));
    close(p[0]);close(o[0]);close(exec);close(null);free(mountinfo);
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--probe")){probe();return 0;}
    REQUIRE(geteuid()==0);
    for(int failure=1;failure<=12;++failure)for(int mask=0;mask<32;++mask)test_fd_failure(failure,mask,0);
    for(int mask=0;mask<32;++mask)test_fd_failure(0,mask,1);
    setup_test(0,0,0,0,0,0);setup_test(33,0,0,0,0,0);
    setup_test(0,1ULL<<10,0,0,0,0);setup_test(33,1ULL<<10,0,0,0,0);
    setup_test(33,0,1,0,0,0);setup_test(33,0,0,0,0,1);
    setup_test(33,0,0,0,0,2);setup_test(33,0,0,SYS_write,0,0);
    const long faults[]={SYS_setsid,SYS_chdir,SYS_prctl,SYS_setgroups,SYS_setresgid,SYS_setresuid,SYS_capset,SYS_getresuid,SYS_getresgid,SYS_getgroups,SYS_capget};
    const unsigned steps[]={1,2,3,5,5,6,7,10,10,10,10};
    for(unsigned i=0;i<sizeof(faults)/sizeof(*faults);++i)setup_test(33,0,0,faults[i],steps[i],0);
    for(unsigned offset=2;offset<=8;++offset){
        next_fault_occurrence=last_cap()+offset;
        unsigned step=offset==2?4:offset==3?8:offset==4?9:10;
        setup_test(33,0,0,SYS_prctl,step,0);
    }
    next_fault_occurrence=1;
    setup_test(33,0,0,SYS_mount,1,0);setup_test(33,0,0,SYS_mount_setattr,1,0);
    puts("phase5-child-ok");return 0;
}
