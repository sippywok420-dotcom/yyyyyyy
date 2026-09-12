// IrisLite - low-level cloaks (C)
// Primary mechanism: __interpose (dyld applies at launch).
// Backup mechanism: GOT rebinding in the main image (constructor, verified addrs).
// Caller-scoped: cloaks only apply when the CALLER is the Snapchat guest image,
// so the LiveContainer host process keeps working normally.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include "got_table.h"

extern void iris_objc_init(void);

// ---------- saved originals ----------
static char *(*g_orig_getenv)(const char *) = 0;
static int (*g_orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = 0;
static int (*g_orig_access)(const char *, int) = 0;
static int (*g_orig_stat)(const char *, struct stat *) = 0;
static int (*g_orig_lstat)(const char *, struct stat *) = 0;
static int (*g_orig_open)(const char *, int, ...) = 0;
static FILE *(*g_orig_fopen)(const char *, const char *) = 0;
static DIR *(*g_orig_opendir)(const char *) = 0;
static int (*g_orig_dladdr)(const void *, Dl_info *) = 0;
static const char *(*g_orig_imgname)(uint32_t) = 0;

static char g_main_path[1024] = {0};

// ---------- helpers ----------
static int has_ins(const char *hay, const char *needle) {
    if (!hay || !needle) return 0;
    size_t nl = strlen(needle), hl = strlen(hay);
    if (nl == 0 || nl > hl) return 0;
    for (size_t i = 0; i + nl <= hl; i++) {
        if (strncasecmp(hay + i, needle, nl) == 0) return 1;
    }
    return 0;
}

// banned in FILE paths (never cloak our own config: IrisLite.plist must stay visible)
static int banned_path(const char *p) {
    return has_ins(p, "livecontainer");
}

// banned in IMAGE names/paths
static int banned_image(const char *p) {
    return has_ins(p, "livecontainer") || has_ins(p, "irislite");
}

// is the direct caller inside the Snapchat guest image?
static int caller_is_guest(void) {
    void *ret = __builtin_return_address(0);
    Dl_info info;
    memset(&info, 0, sizeof(info));
    int (*rdl)(const void *, Dl_info *) = g_orig_dladdr;
    if (!rdl) {
        rdl = (int (*)(const void *, Dl_info *))dlsym(RTLD_NEXT, "dladdr");
        if (!rdl) return 0;
    }
    if (rdl(ret, &info) == 0 || !info.dli_fname) return 0;
    return has_ins(info.dli_fname, "Snapchat.app") ? 1 : 0;
}

static void *next_orig(const char *name) {
    return dlsym(RTLD_NEXT, name);
}

// ---------- hooks ----------
static char *my_getenv(const char *name) {
    if (name && strncmp(name, "DYLD_", 5) == 0) {
        if (caller_is_guest()) return 0;
    }
    char *(*f)(const char *) = g_orig_getenv;
    if (!f) f = (char *(*)(const char *))next_orig("getenv");
    return f ? f(name) : 0;
}

static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int (*f)(int *, u_int, void *, size_t *, void *, size_t) = g_orig_sysctl;
    if (!f) f = (int (*)(int *, u_int, void *, size_t *, void *, size_t))next_orig("sysctl");
    if (!f) { errno = ENOMEM; return -1; }
    int r = f(name, namelen, oldp, oldlenp, newp, newlen);
    if (r == 0 && name && namelen >= 4 && name[0] == CTL_KERN &&
        name[1] == KERN_PROC && name[2] == KERN_PROC_PID &&
        oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
        // scrub the traced flag: debugger/JIT presence stays invisible
        ((struct kinfo_proc *)oldp)->kp_proc.p_flag &= ~((int)P_TRACED);
    }
    return r;
}

static int my_access(const char *path, int mode) {
    if (path && banned_path(path) && caller_is_guest()) { errno = ENOENT; return -1; }
    int (*f)(const char *, int) = g_orig_access;
    if (!f) f = (int (*)(const char *, int))next_orig("access");
    if (!f) { errno = ENOENT; return -1; }
    return f(path, mode);
}

static int my_stat(const char *path, struct stat *buf) {
    if (path && banned_path(path) && caller_is_guest()) { errno = ENOENT; return -1; }
    int (*f)(const char *, struct stat *) = g_orig_stat;
    if (!f) f = (int (*)(const char *, struct stat *))next_orig("stat");
    if (!f) { errno = ENOENT; return -1; }
    return f(path, buf);
}

static int my_lstat(const char *path, struct stat *buf) {
    if (path && banned_path(path) && caller_is_guest()) { errno = ENOENT; return -1; }
    int (*f)(const char *, struct stat *) = g_orig_lstat;
    if (!f) f = (int (*)(const char *, struct stat *))next_orig("lstat");
    if (!f) { errno = ENOENT; return -1; }
    return f(path, buf);
}

static int my_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path && banned_path(path) && caller_is_guest()) { errno = ENOENT; return -1; }
    int (*f)(const char *, int, ...) = g_orig_open;
    if (!f) f = (int (*)(const char *, int, ...))next_orig("open");
    if (!f) { errno = ENOENT; return -1; }
    if (flags & O_CREAT) return f(path, flags, mode);
    return f(path, flags);
}

static FILE *my_fopen(const char *path, const char *mode) {
    if (path && banned_path(path) && caller_is_guest()) { errno = ENOENT; return 0; }
    FILE *(*f)(const char *, const char *) = g_orig_fopen;
    if (!f) f = (FILE *(*)(const char *, const char *))next_orig("fopen");
    return f ? f(path, mode) : 0;
}

static DIR *my_opendir(const char *path) {
    if (path && banned_path(path) && caller_is_guest()) { errno = ENOENT; return 0; }
    DIR *(*f)(const char *) = g_orig_opendir;
    if (!f) f = (DIR *(*)(const char *))next_orig("opendir");
    return f ? f(path) : 0;
}

static int my_dladdr(const void *addr, Dl_info *info) {
    int (*f)(const void *, Dl_info *) = g_orig_dladdr;
    if (!f) f = (int (*)(const void *, Dl_info *))next_orig("dladdr");
    if (!f) return 0;
    int r = f(addr, info);
    if (r != 0 && info->dli_fname && banned_image(info->dli_fname) && caller_is_guest()) {
        info->dli_fname = g_main_path[0] ? g_main_path : info->dli_fname;
    }
    return r;
}

static const char *my_imgname(uint32_t idx) {
    const char *(*f)(uint32_t) = g_orig_imgname;
    if (!f) f = (const char *(*)(uint32_t))next_orig("_dyld_get_image_name");
    const char *r = f ? f(idx) : 0;
    if (r && banned_image(r) && caller_is_guest()) {
        return g_main_path[0] ? g_main_path : r;
    }
    return r;
}

// ---------- __interpose ----------
struct interpose { const void *newf; const void *orig; };
#define INTERPOSE(hook, orig) \
    static const struct interpose _ip_##hook __attribute__((used, section("__DATA,__interpose"))) = \
        { (const void *)(unsigned long)&my_##hook, (const void *)(unsigned long)&orig }

INTERPOSE(getenv, getenv);
INTERPOSE(sysctl, sysctl);
INTERPOSE(access, access);
INTERPOSE(stat, stat);
INTERPOSE(lstat, lstat);
INTERPOSE(open, open);
INTERPOSE(fopen, fopen);
INTERPOSE(opendir, opendir);
INTERPOSE(dladdr, dladdr);
INTERPOSE(imgname, _dyld_get_image_name);

// ---------- GOT backup patch ----------
static void patch_one(unsigned long long unslid, void *hook, void **save) {
    long slide = _dyld_get_image_vmaddr_slide(0);
    void **loc = (void **)(unsigned long long)(unslid + (unsigned long long)slide);
    *save = *loc;
    vm_address_t page = (vm_address_t)loc & ~((vm_address_t)0x3FFF);
    vm_protect(mach_task_self(), page, (vm_size_t)0x4000, FALSE,
               VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    *loc = hook;
    vm_protect(mach_task_self(), page, (vm_size_t)0x4000, FALSE, VM_PROT_READ);
}

__attribute__((constructor))
static void iris_init(void) {
    patch_one(GOT_GETENV, (void *)my_getenv, (void **)&g_orig_getenv);
    patch_one(GOT_SYSCTL, (void *)my_sysctl, (void **)&g_orig_sysctl);
    patch_one(GOT_ACCESS, (void *)my_access, (void **)&g_orig_access);
    patch_one(GOT_STAT, (void *)my_stat, (void **)&g_orig_stat);
    patch_one(GOT_LSTAT, (void *)my_lstat, (void **)&g_orig_lstat);
    patch_one(GOT_OPEN, (void *)my_open, (void **)&g_orig_open);
    patch_one(GOT_FOPEN, (void *)my_fopen, (void **)&g_orig_fopen);
    patch_one(GOT_OPENDIR, (void *)my_opendir, (void **)&g_orig_opendir);
    patch_one(GOT_DLADDR, (void *)my_dladdr, (void **)&g_orig_dladdr);
    patch_one(GOT_DYLD_GET_IMAGE_NAME, (void *)my_imgname, (void **)&g_orig_imgname);

    if (g_orig_imgname) {
        const char *mp = g_orig_imgname(0);
        if (mp) {
            strncpy(g_main_path, mp, sizeof(g_main_path) - 1);
            g_main_path[sizeof(g_main_path) - 1] = '\0';
        }
    }

    iris_objc_init();
}
