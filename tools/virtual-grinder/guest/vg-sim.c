/*
 * libvgsim.so — emulation-only LD_PRELOAD shim for the E64 WS HMI.
 *
 * Three independent virtualizations, all documented as emulation-only and
 * never loaded on real hardware:
 *
 *  1. /dev/mem  — the STM32 MPC157 driver opens /dev/mem and mmaps peripheral
 *     registers. Under QEMU those physical pages do not exist. Redirect the
 *     open to a sparse memfd and fall back to anonymous memory when mmap
 *     fails, so register reads return zero instead of aborting.
 *
 *  2. /sys/class/input/input1/device/gpio_value — the vendor-patched gpio-keys
 *     attribute has write-index/read-state semantics that a plain file cannot
 *     provide. Intercept open/read/write on that path and serve key state from
 *     /tmp/vg/keys (written by vg-agent).
 *
 *  3. SystemIo::At24c16Driver::readEncryptedDevicePK() — the per-machine EDPK
 *     is provisioned in the device tree and cannot be synthesized. Returning a
 *     valid empty QByteArray lets the HMI continue with an unprovisioned
 *     identity instead of dereferencing uninitialized stack memory.
 *
 *  4. Optional hardware-path audit: every open() of an IIO/PWM/timer sysfs file
 *     is appended once to /tmp/vg/hw.log. This is how the virtual-hardware
 *     model in vg-agent was matched to the paths the vendor HMI really uses;
 *     it is bounded (512 paths) and has no effect on the data path.
 *
 * Build (glibc <= 2.34, armhf):
 *   gcc -shared -fPIC -O2 -o libvgsim.so vg-sim.c -ldl -pthread
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define KEYS_FILE "/tmp/vg/keys"
#define MAX_TRACKED 64

/* ------------------------------------------------------------ logging */

static void shim_log(const char *fmt, ...) {
    static int fd = -2;
    if (fd == -2) fd = open("/tmp/vg/shim.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n > 0) { (void)!write(fd, buf, (size_t)n); (void)!write(fd, "\n", 1); }
}

/* --------------------------------------------------------- /dev/mem */

static int is_mem_dev(const char *p) {
    return p && (strcmp(p, "/dev/mem") == 0 || strcmp(p, "/dev/kmem") == 0);
}

static int make_memfd(void) {
    int fd = (int)syscall(SYS_memfd_create, "vg-mem", MFD_CLOEXEC);
    if (fd >= 0) {
        if (ftruncate(fd, 0x60000000ULL) != 0) { /* sparse, best effort */ }
    }
    return fd;
}

/* ------------------------------------------------------ gpio_value */

struct tracked {
    int fd;
    int index;
};

static struct tracked g_tracked[MAX_TRACKED];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int is_gpio_value(const char *path) {
    return path && strstr(path, "/sys/class/input/") && strstr(path, "/gpio_value");
}

static int track_fd(int fd) {
    if (fd < 0) return fd;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (g_tracked[i].fd == 0) {
            g_tracked[i].fd = fd + 1; /* fd 0 is a valid descriptor */
            g_tracked[i].index = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return fd;
}

static struct tracked *lookup(int fd) {
    struct tracked *found = NULL;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (g_tracked[i].fd == fd + 1) { found = &g_tracked[i]; break; }
    }
    pthread_mutex_unlock(&g_lock);
    return found;
}

static void untrack(int fd) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (g_tracked[i].fd == fd + 1) { g_tracked[i].fd = 0; break; }
    }
    pthread_mutex_unlock(&g_lock);
}

static int gpio_open(const char *path, int flags, mode_t mode) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "open64");
    if (!real) real = dlsym(RTLD_NEXT, "open");
    int fd = (int)syscall(SYS_memfd_create, "vg-gpio", MFD_CLOEXEC);
    if (fd < 0) return real ? real(path, flags, mode) : -1;
    (void)!write(fd, "0\n", 2);
    lseek(fd, 0, SEEK_SET);
    track_fd(fd);
    shim_log("gpio_value open -> fd %d", fd);
    return fd;
}

static ssize_t gpio_read(int fd, void *buf, size_t count) {
    struct tracked *t = lookup(fd);
    if (!t) return -1;
    if (count == 0) return 0;
    char keys[32] = "00000000";
    int kfd = open(KEYS_FILE, O_RDONLY);
    if (kfd >= 0) {
        ssize_t n = read(kfd, keys, sizeof(keys) - 1);
        if (n > 0) keys[n] = 0;
        close(kfd);
    }
    int idx = t->index;
    if (idx < 0) idx = 0;
    if (idx > 7) idx = 7;
    char value = keys[idx] == '1' ? '1' : '0';
    ((char *)buf)[0] = value;
    return 1;
}

static ssize_t gpio_write(int fd, const void *buf, size_t count) {
    struct tracked *t = lookup(fd);
    if (!t) return -1;
    if (count == 0) return 0;
    const char *p = (const char *)buf;
    int idx = 0;
    for (size_t i = 0; i < count && p[i] >= '0' && p[i] <= '9'; i++)
        idx = idx * 10 + (p[i] - '0');
    t->index = idx;
    shim_log("gpio_value write index=%d", idx);
    return (ssize_t)count;
}

/* ------------------------------------------------------ hardware audit */

#define HW_LOG "/tmp/vg/hw.log"
#define HW_MAX 512
#define HW_PATH_MAX 192

static char g_hw_paths[HW_MAX][HW_PATH_MAX];
static int g_hw_count;
static pthread_mutex_t g_hw_lock = PTHREAD_MUTEX_INITIALIZER;

static int hw_interesting(const char *path) {
    if (!path) return 0;
    if (strstr(path, "/dev/iio")) return 1;
    if (!strstr(path, "/sys/")) return 0;
    return strstr(path, "in_voltage") != NULL ||
           strstr(path, "/capture") != NULL ||
           strstr(path, "/count") != NULL ||
           strstr(path, "/function") != NULL ||
           strstr(path, "buffer/") != NULL ||
           strstr(path, "trigger/") != NULL ||
           strstr(path, "scan_elements") != NULL;
}

static void hw_trace(const char *path, int result) {
    if (!hw_interesting(path)) return;
    char key[HW_PATH_MAX + 16];
    snprintf(key, sizeof(key), "%s#%d", path, result);
    pthread_mutex_lock(&g_hw_lock);
    for (int i = 0; i < g_hw_count; i++) {
        if (strcmp(g_hw_paths[i], key) == 0) {
            pthread_mutex_unlock(&g_hw_lock);
            return;
        }
    }
    if (g_hw_count >= HW_MAX) {
        pthread_mutex_unlock(&g_hw_lock);
        return;
    }
    snprintf(g_hw_paths[g_hw_count], HW_PATH_MAX, "%s", key);
    g_hw_count++;
    pthread_mutex_unlock(&g_hw_lock);

    char buf[HW_PATH_MAX + 64];
    int n = snprintf(buf, sizeof(buf), "pid=%d open %s -> %d\n",
                     (int)getpid(), path, result);
    if (n <= 0) return;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, HW_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        (void)!write(fd, buf, (size_t)n);
        close(fd);
    }
}


/* ------------------------------------------------------ crash forensics */

static void crash_handler(int sig, siginfo_t *si, void *uc) {
    int fd = open("/tmp/vg/crash.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        char buf[1024];
        ucontext_t *u = (ucontext_t *)uc;
        int n = snprintf(buf, sizeof(buf),
                         "signal=%d addr=%p pc=%p lr=%p sp=%p\n",
                         sig, si ? si->si_addr : NULL,
                         (void *)(uintptr_t)u->uc_mcontext.arm_pc,
                         (void *)(uintptr_t)u->uc_mcontext.arm_lr,
                         (void *)(uintptr_t)u->uc_mcontext.arm_sp);
        if (n > 0) (void)!write(fd, buf, (size_t)n);
        Dl_info di;
        if (dladdr((void *)(uintptr_t)u->uc_mcontext.arm_pc, &di) && di.dli_fname) {
            n = snprintf(buf, sizeof(buf), "pc in %s+0x%lx\n", di.dli_fname,
                         (unsigned long)((uintptr_t)u->uc_mcontext.arm_pc - (uintptr_t)di.dli_fbase));
            if (n > 0) (void)!write(fd, buf, (size_t)n);
        }
        if (dladdr((void *)(uintptr_t)u->uc_mcontext.arm_lr, &di) && di.dli_fname) {
            n = snprintf(buf, sizeof(buf), "lr in %s+0x%lx\n", di.dli_fname,
                         (unsigned long)((uintptr_t)u->uc_mcontext.arm_lr - (uintptr_t)di.dli_fbase));
            if (n > 0) (void)!write(fd, buf, (size_t)n);
        }
        int mfd = open("/proc/self/maps", O_RDONLY);
        if (mfd >= 0) {
            char mbuf[8192];
            ssize_t got = read(mfd, mbuf, sizeof(mbuf) - 1);
            close(mfd);
            if (got > 0) {
                mbuf[got] = 0;
                char *save = NULL;
                for (char *line = strtok_r(mbuf, "\n", &save); line;
                     line = strtok_r(NULL, "\n", &save)) {
                    if (strstr(line, "libNgxUi") || strstr(line, "NgxUiApp") ||
                        strstr(line, "libc.so")) {
                        n = snprintf(buf, sizeof(buf), "  map %s\n", line);
                        if (n > 0) (void)!write(fd, buf, (size_t)n);
                    }
                }
            }
        }
        void *frames[32];
        int count = backtrace(frames, 32);
        for (int i = 0; i < count; i++) {
            Dl_info info;
            if (dladdr(frames[i], &info) && info.dli_fname) {
                n = snprintf(buf, sizeof(buf), "  #%d %s+0x%lx (%p)\n", i,
                             info.dli_fname,
                             (unsigned long)((uintptr_t)frames[i] - (uintptr_t)info.dli_fbase),
                             frames[i]);
            } else {
                n = snprintf(buf, sizeof(buf), "  #%d %p\n", i, frames[i]);
            }
            if (n > 0) (void)!write(fd, buf, (size_t)n);
        }
        close(fd);
    }
    _exit(128 + sig);
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    static int (*real)(int, const struct sigaction *, struct sigaction *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "sigaction");
    if (signum == SIGSEGV || signum == SIGABRT || signum == SIGBUS || signum == SIGILL) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = crash_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
        sigemptyset(&sa.sa_mask);
        return real(signum, &sa, oldact);
    }
    return real(signum, act, oldact);
}

typedef void (*sighandler_fn)(int);
sighandler_fn signal(int signum, sighandler_fn handler) {
    static sighandler_fn (*real)(int, sighandler_fn) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "signal");
    if (signum == SIGSEGV || signum == SIGABRT || signum == SIGBUS || signum == SIGILL) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = crash_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
        sigemptyset(&sa.sa_mask);
        struct sigaction old;
        int rc = sigaction(signum, &sa, &old);
        return rc == 0 ? (old.sa_flags & SA_SIGINFO ? (sighandler_fn)old.sa_sigaction
                                                    : old.sa_handler)
                       : SIG_ERR;
    }
    return real(signum, handler);
}

/* ------------------------------------------- readEncryptedDevicePK */
typedef void (*qbytearray_ctor_t)(void *self, const char *data, int size);

void vg_read_edpk(void *ret, const void *self)
    __asm__("_ZNK8SystemIo13At24c16Driver21readEncryptedDevicePKEv");

void vg_read_edpk(void *ret, const void *self) {
    (void)self;
    static qbytearray_ctor_t ctor = NULL;
    if (!ctor) ctor = (qbytearray_ctor_t)dlsym(RTLD_DEFAULT, "_ZN10QByteArrayC1EPKci");
    if (!ctor) ctor = (qbytearray_ctor_t)dlsym(RTLD_DEFAULT, "_ZN10QByteArrayC2EPKci");
    if (ctor) {
        ctor(ret, "", 0);
        shim_log("readEncryptedDevicePK -> empty QByteArray");
    } else {
        /* Last resort: null d-pointer. Should never happen with Qt 5. */
        *(void **)ret = NULL;
        shim_log("readEncryptedDevicePK -> NULL (QByteArray ctor not found)");
    }
}

/* --------------------------------------------------- sysfs read audit */

/* The ADC drivers read a small sysfs attribute once at create (scale, offset,
 * raw) and cache the value. Log the actual bytes so the fixture can be matched
 * to what the vendor parser expects. */
struct rtrack {
    int fd;
    int logged;
    char path[HW_PATH_MAX];
};
#define RTRACK_MAX 128
static struct rtrack g_rtrack[RTRACK_MAX];
static pthread_mutex_t g_rtrack_lock = PTHREAD_MUTEX_INITIALIZER;

static int is_sysfs_scalar(const char *path) {
    if (!path) return 0;
    if (strstr(path, "in_voltage")) return 1;
    /* Any small sysfs attribute the vendor polls repeatedly: capture, count,
     * enable, function, brightness, value, period, duty_cycle. */
    static const char *const names[] = {
        "/capture", "/count", "/enable", "/function", "/brightness",
        "/value", "/bl_power", "/period", "/duty_cycle", NULL
    };
    for (int i = 0; names[i]; i++)
        if (strstr(path, names[i])) return 1;
    return 0;
}

static void rtrack_add(int fd, const char *path) {
    if (fd < 0 || !is_sysfs_scalar(path)) return;
    pthread_mutex_lock(&g_rtrack_lock);
    for (int i = 0; i < RTRACK_MAX; i++) {
        if (g_rtrack[i].fd == 0) {
            g_rtrack[i].fd = fd + 1;
            g_rtrack[i].logged = 0;
            snprintf(g_rtrack[i].path, HW_PATH_MAX, "%s", path);
            break;
        }
    }
    pthread_mutex_unlock(&g_rtrack_lock);
}

static struct rtrack *rtrack_lookup(int fd) {
    struct rtrack *found = NULL;
    pthread_mutex_lock(&g_rtrack_lock);
    for (int i = 0; i < RTRACK_MAX; i++) {
        if (g_rtrack[i].fd == fd + 1) { found = &g_rtrack[i]; break; }
    }
    pthread_mutex_unlock(&g_rtrack_lock);
    return found;
}

static void rtrack_del(int fd) {
    pthread_mutex_lock(&g_rtrack_lock);
    for (int i = 0; i < RTRACK_MAX; i++) {
        if (g_rtrack[i].fd == fd + 1) { g_rtrack[i].fd = 0; break; }
    }
    pthread_mutex_unlock(&g_rtrack_lock);
}

static void rtrack_note_read(struct rtrack *t, const void *buf, ssize_t n) {
    if (!t || t->logged || n < 0) return;
    t->logged = 1;
    char val[96];
    size_t j = 0;
    const unsigned char *p = (const unsigned char *)buf;
    for (ssize_t i = 0; i < n && j + 1 < sizeof(val); i++)
        val[j++] = (p[i] >= 0x20 && p[i] < 0x7f) ? (char)p[i] : '.';
    val[j] = 0;
    char line[HW_PATH_MAX + 128];
    int len = snprintf(line, sizeof(line), "read %s = '%s' (%zd)\n", t->path, val, n);
    if (len <= 0) return;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, HW_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        (void)!write(fd, line, (size_t)len);
        close(fd);
    }
}

/* ------------------------------------------------ fan calibration guard */

/* On this board revision the vendor builds FanCalibration with a null
 * FanDriver (the fan block is created later in main), so CalibrateFan1
 * dereferences NULL in FanDriver::setPwmDuty and the HMI dies. Keep the
 * calibration state machine alive and drive the vg-agent fan model through
 * the same PWM/capture sysfs files the real FanDriver would use. */
static int g_null_fan = 1;

static const char *fan_pwm_dir(int fan) {
    return fan == 2
        ? "/sys/devices/platform/soc/40007000.timer/40007000.timer:pwm/pwm/pwmchip0/pwm10"
        : "/sys/devices/platform/soc/40006000.timer/40006000.timer:pwm/pwm/pwmchip0/pwm8";
}

static const char *fan_capture(int fan) {
    return fan == 2
        ? "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip4/pwm3/capture"
        : "/sys/devices/platform/soc/40002000.timer/40002000.timer:pwm/pwm/pwmchip0/pwm2/capture";
}

static void write_text(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd >= 0) {
        (void)!write(fd, text, strlen(text));
        close(fd);
    }
}

void _ZN13JsonConnector20startFan1CalibrationEv(void *self)
    __asm__("_ZN13JsonConnector20startFan1CalibrationEv");

void _ZN13JsonConnector20startFan1CalibrationEv(void *self) {
    static void (*real)(void *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_ZN13JsonConnector20startFan1CalibrationEv");
    g_null_fan = 1;
    if (real) real(self);
}

void _ZN13JsonConnector20startFan2CalibrationEv(void *self)
    __asm__("_ZN13JsonConnector20startFan2CalibrationEv");

void _ZN13JsonConnector20startFan2CalibrationEv(void *self) {
    static void (*real)(void *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_ZN13JsonConnector20startFan2CalibrationEv");
    g_null_fan = 2;
    if (real) real(self);
}

void _ZN8SystemIo9FanDriver10setPwmDutyEi(void *self, int duty)
    __asm__("_ZN8SystemIo9FanDriver10setPwmDutyEi");

void _ZN8SystemIo9FanDriver10setPwmDutyEi(void *self, int duty) {
    static void (*real)(void *, int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_ZN8SystemIo9FanDriver10setPwmDutyEi");
    if (!self) {
        int d = duty < 0 ? 0 : (duty > 100 ? 100 : duty);
        char p[256], v[32];
        snprintf(p, sizeof(p), "%s/duty_cycle", fan_pwm_dir(g_null_fan));
        snprintf(v, sizeof(v), "%d\n", d * 400);
        write_text(p, v);
        snprintf(p, sizeof(p), "%s/enable", fan_pwm_dir(g_null_fan));
        write_text(p, d ? "1\n" : "0\n");
        shim_log("FanDriver::setPwmDuty(NULL, %d) -> modelled PWM", duty);
        return;
    }
    if (real) real(self, duty);
}

int _ZN8SystemIo9FanDriver8tachoRpmEv(void *self)
    __asm__("_ZNK8SystemIo9FanDriver8tachoRpmEv");

int _ZN8SystemIo9FanDriver8tachoRpmEv(void *self) {
    static int (*real)(void *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_ZNK8SystemIo9FanDriver8tachoRpmEv");
    if (!self) {
        char b[64] = {0};
        int fd = open(fan_capture(g_null_fan), O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, b, sizeof(b) - 1);
            close(fd);
            if (n > 0) b[n] = 0;
        }
        long period = strtol(b, NULL, 10);
        int rpm = period > 0 ? (int)(30000000000.0 / (double)period + 0.5) : 0;
        shim_log("FanDriver::tachoRpm(NULL) -> %d (capture '%s')", rpm, b);
        return rpm;
    }
    return real ? real(self) : 0;
}

void _ZN8SystemIo14FanCalibration18triggerCalibrationEv(void *self)
    __asm__("_ZN8SystemIo14FanCalibration18triggerCalibrationEv");

void _ZN8SystemIo14FanCalibration18triggerCalibrationEv(void *self) {
    static void (*real)(void *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_ZN8SystemIo14FanCalibration18triggerCalibrationEv");
    if (self) {
        void *fan = *(void **)((char *)self + 0x18);
        shim_log("FanCalibration::triggerCalibration self=%p fan=%p", self, fan);
    } else {
        shim_log("FanCalibration::triggerCalibration(NULL) ignored");
        return;
    }
    if (real) real(self);
}

/* --------------------------------------------------------- open/read/write */

int open(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "open");
    if (is_mem_dev(path)) return make_memfd();
    if (is_gpio_value(path)) return gpio_open(path, flags, 0);
    va_list ap; va_start(ap, flags);
    mode_t mode = (mode_t)va_arg(ap, int); va_end(ap);
    int fd = real(path, flags, mode);
    hw_trace(path, fd);
    rtrack_add(fd, path);
    return fd;
}

int open64(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "open64");
    if (is_mem_dev(path)) return make_memfd();
    if (is_gpio_value(path)) return gpio_open(path, flags, 0);
    va_list ap; va_start(ap, flags);
    mode_t mode = (mode_t)va_arg(ap, int); va_end(ap);
    int fd = real(path, flags, mode);
    hw_trace(path, fd);
    rtrack_add(fd, path);
    return fd;
}

int openat(int dirfd, const char *path, int flags, ...) {
    static int (*real)(int, const char *, int, ...) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "openat");
    if (is_mem_dev(path)) return make_memfd();
    if (is_gpio_value(path)) return gpio_open(path, flags, 0);
    va_list ap; va_start(ap, flags);
    mode_t mode = (mode_t)va_arg(ap, int); va_end(ap);
    int fd = real(dirfd, path, flags, mode);
    hw_trace(path, fd);
    rtrack_add(fd, path);
    return fd;
}

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real)(int, void *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "read");
    if (lookup(fd)) return gpio_read(fd, buf, count);
    struct rtrack *t = rtrack_lookup(fd);
    ssize_t n = real(fd, buf, count);
    if (t) {
        rtrack_note_read(t, buf, n);
        /* sysfs attributes restart at offset 0 on every read; a regular file
         * keeps its position and would return 0 on the second read. */
        (void)!lseek(fd, 0, SEEK_SET);
    }
    return n;
}

ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real)(int, const void *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "write");
    if (lookup(fd)) return gpio_write(fd, buf, count);
    return real(fd, buf, count);
}

int close(int fd) {
    static int (*real)(int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "close");
    untrack(fd);
    rtrack_del(fd);
    return real(fd);
}

/* --------------------------------------------------------- mmap fallback */

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    static void *(*real)(void *, size_t, int, int, int, off_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "mmap");
    void *p = real(addr, len, prot, flags, fd, off);
    if (p == MAP_FAILED) {
        p = real(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) shim_log("mmap fallback len=%zu", len);
    }
    return p;
}

void *mmap64(void *addr, size_t len, int prot, int flags, int fd, off64_t off) {
    static void *(*real)(void *, size_t, int, int, int, off64_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "mmap64");
    void *p = real(addr, len, prot, flags, fd, off);
    if (p == MAP_FAILED) {
        p = real(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) shim_log("mmap64 fallback len=%zu", len);
    }
    return p;
}
