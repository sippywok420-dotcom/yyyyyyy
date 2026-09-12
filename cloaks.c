// IrisLite - low-level cloaks, v2 (C)
// Primary mechanism: GOT rebinding in the main image (verified addrs, table-driven).
// Backup mechanism: __interpose (dyld applies at launch where honored).
// Init-safety: every hook resolves its original through the table. Entries not
// yet rebound read the still-pristine GOT (safe: dyld bound it at launch);
// rebound entries use the saved original. No dlsym before init, no recursion.
// Caller-scoped: cloaks only apply when the CALLER is the Snapchat guest image,
// so the host process and system frameworks keep working normally.

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

// ---------- hook table ----------
enum {
    H_GETENV = 0,
    H_SYSCTL,
    H_ACCESS,
    H_STAT,
    H_LSTAT,
    H_OPEN,
    H_FOPEN,
    H_OPENDIR,
    H_DLADDR,
    H_IMGNAME,
    H_COUNT
};

static const unsigned long long kGot[H_COUNT] = {
    GOT_GETENV, GOT_SYSCTL, GOT_ACCESS, GOT_STAT, GOT_LSTAT,
    GOT_OPEN, GOT_FOPEN, GOT_OPENDIR, GOT_DLADDR, GOT_DYLD_GET_IMAGE_NAME
};

static void *g_saved[H_COUNT] = {0};
static int g_done[H_COUNT] = {0};

// original for entry i: saved copy once rebound, else live (pristine) GOT value
static void *orig_of(int idx) {
    if (g_done[idx]) return g_saved[idx];
    long slide = _dyld_get_image_vmaddr_slide(0);
    void **loc = (void **)(unsigned long long)(kGot[idx] + (unsigned long long)slide);
    return *loc;
}

static void *next_orig(const char *name) {
    return dlsym(RTLD_NEXT, name);
}

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

// banned in FILE paths (our own config IrisLite.plist must stay visible)
static int banned_path(const char *p) {
    return has_ins(p, "livecontainer");
}

// banned in IMAGE names/paths
static int banned_image(const char *p) {
    return has_ins(p, "livecontainer") || has_ins(p, "irislite");
}

static void *orig_dladdr_fn(void) {
    void *f = orig_of(H_DLADDR);
    if (!f) f = next_orig("dladdr");
    return f;
}

// is the direct caller inside the Snapchat guest image?
static int caller_is_guest(void) {
    void *ret = __builtin_return_address(0);
    Dl_info info;
    memset(&info, 0, sizeof(info));
    int (*rdl)(const void *, Dl_info *) =
        (int (*)(const void *, Dl_info *))orig_dladdr_fn();
    if (!rdl) return 0;
    if (rdl(ret, &info) == 0 || !info.dli_fname) return 0;
    return has_ins(info.dli_fname, "Snapchat.app") ? 1 : 0;
}

// ---------- hooks ----------
static char *my_getenv(const char *name) {
    if (name && strncmp(name, "DYLD_", 5) == 0) {
        if (caller_is_guest()) return 0;
    }
    char *(*f)(const char *) = (char *(*)(const char *))orig_of(H_GETENV);
    if (!f) f = (char *(*)(const char *))next_orig("getenv");
    return f ? f(name) : 0;
}

static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int (*f)(int *, u_int, void *, size_t *, void *, size_t) =
        (int (*)(int *, u_int, void *, size_t *, void *, size_t))orig_of(H_SYSCTL);
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
    int (*f)(const char *, int) = (int (*)(const char *, int))orig_of(H_ACCESS);
    if (!f) f = (int (*)(const char *, int))next_orig("access");
    if (!f) { errno = ENOENT; return -1; }
    return f(path, mode);
}

static int my_stat(const char *path, struct stat *buf) {
    if (path && banned_path(path) && caller_is_guest()) { errno = ENOENT; return -1; }
    int (*f)(const char *, struct stat *) = (int (*)(const char *, struct stat *))orig_of(H_STAT);
    if (!f) f = (int (*)(const char *, struct stat *))next_orig("stat");
    if (!f) { errno = ENOENT; return -1; }
    return f(path, buf);
}

static int my_lstat(const char *path, struct stat *buf) {
    if (path && banned_path(path) && caller_is_guest()) { errno = ENOENT; return -1; }
    int (*f)(const char *, struct stat *) = (int (*)(const char *, struct stat *))orig_of(H_LSTAT);
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
    int (*f)(const char *, int, ...) = (int (*)(const char *, int, ...))orig_of(H_OPEN);
    if (!f) f = (int (*)(const char *, int, ...))next_orig("open");
    if (!f) { errno = ENOENT; return -1; }
    if (flags & O_CREAT) return f(path, flags, mode);
    return f(path, flags);
}

static FILE *my_fopen(const char *path, const char *mode) {
    if (path && banned_path(path) && caller_is_guest()) { errno = ENOENT; return 0; }
    FILE *(*f)(const char *, const char *) = (FILE *(*)(const char *, const char *))orig_of(H_FOPEN);
    if (!f) f = (FILE *(*)(const char *, const char *))next_orig("fopen");
    return f ? f(path, mode) : 0;
}

static DIR *my_opendir(const char *path) {
    if (path && banned_path(path) && caller_is_guest()) { errno = ENOENT; return 0; }
    DIR *(*f)(const char *) = (DIR *(*)(const char *))orig_of(H_OPENDIR);
    if (!f) f = (DIR *(*)(const char *))next_orig("opendir");
    return f ? f(path) : 0;
}

static int my_dladdr(const void *addr, Dl_info *info) {
    int (*f)(const void *, Dl_info *) = (int (*)(const void *, Dl_info *))orig_of(H_DLADDR);
    if (!f) f = (int (*)(const void *, Dl_info *))next_orig("dladdr");
    if (!f) return 0;
    int r = f(addr, info);
    if (r != 0 && info->dli_fname && banned_image(info->dli_fname) && caller_is_guest()) {
        if (g_main_path[0]) info->dli_fname = g_main_path;
    }
    return r;
}

static const char *my_imgname(uint32_t idx) {
    const char *(*f)(uint32_t) = (const char *(*)(uint32_t))orig_of(H_IMGNAME);
    if (!f) f = (const char *(*)(uint32_t))next_orig("_dyld_get_image_name");
    const char *r = f ? f(idx) : 0;
    if (r && banned_image(r) && caller_is_guest()) {
        return g_main_path[0] ? g_main_path : r;
    }
    return r;
}

// ---------- __interpose (backup path; honored by dyld where applicable) ----------
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

// ---------- constructor ----------
static void *g_hooks[H_COUNT] = {0};

__attribute__((constructor))
static void iris_init(void) {
    g_hooks[H_GETENV] = (void *)my_getenv;
    g_hooks[H_SYSCTL] = (void *)my_sysctl;
    g_hooks[H_ACCESS] = (void *)my_access;
    g_hooks[H_STAT] = (void *)my_stat;
    g_hooks[H_LSTAT] = (void *)my_lstat;
    g_hooks[H_OPEN] = (void *)my_open;
    g_hooks[H_FOPEN] = (void *)my_fopen;
    g_hooks[H_OPENDIR] = (void *)my_opendir;
    g_hooks[H_DLADDR] = (void *)my_dladdr;
    g_hooks[H_IMGNAME] = (void *)my_imgname;

    long slide = _dyld_get_image_vmaddr_slide(0);
    for (int i = 0; i < H_COUNT; i++) {
        void **loc = (void **)(unsigned long long)(kGot[i] + (unsigned long long)slide);
        void *cur = *loc;
        // validate: must resolve inside a system library, else skip this entry
        Dl_info info;
        memset(&info, 0, sizeof(info));
        int ok = 0;
        {
            int (*rdl)(const void *, Dl_info *) =
                (int (*)(const void *, Dl_info *))orig_of(H_DLADDR);
            if (!rdl) rdl = (int (*)(const void *, Dl_info *))next_orig("dladdr");
            if (rdl && cur && rdl(cur, &info) != 0 && info.dli_fname) {
                if (has_ins(info.dli_fname, "/usr/lib/") ||
                    has_ins(info.dli_fname, "/System/Library/")) ok = 1;
            }
        }
        if (!ok) continue;
        g_saved[i] = cur;
        g_done[i] = 1;
        vm_address_t page = (vm_address_t)loc & ~((vm_address_t)0x3FFF);
        vm_protect(mach_task_self(), page, (vm_size_t)0x4000, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        *loc = g_hooks[i];
        vm_protect(mach_task_self(), page, (vm_size_t)0x4000, FALSE, VM_PROT_READ);
    }

    if (g_done[H_IMGNAME] && g_saved[H_IMGNAME]) {
        const char *(*f)(uint32_t) = (const char *(*)(uint32_t))g_saved[H_IMGNAME];
        const char *mp = f(0);
        if (mp) {
            strncpy(g_main_path, mp, sizeof(g_main_path) - 1);
            g_main_path[sizeof(g_main_path) - 1] = '\0';
        }
    }

    iris_objc_init();
}
