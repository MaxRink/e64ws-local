/*
 * vg-agent — guest-side virtual grinder device agent.
 *
 * Runs as root from /etc/init.d/S00vgagent inside the QEMU VM. It owns every
 * hardware surface the vendor HMI expects but the VM cannot provide:
 *
 *   - tmpfs overlays over the sysfs subtrees the HMI reads/writes
 *     (leds, backlight, gpio, iio, platform timers, nvmem)
 *   - a uinput EV_REL device that becomes /dev/input/event0 (rotary encoder)
 *   - /dev/watchdog as a regular file (the HMI only open/write()s it)
 *   - the fake key-state file consumed by the LD_PRELOAD shim
 *   - a line-oriented control channel on a virtio-serial port
 *
 * It never touches real hardware: every value it exposes is synthetic and
 * lives under /tmp/vg or in the tmpfs overlays. Build static (musl) and install
 * at /usr/sbin/vg-agent.
 *
 * Control protocol: one ASCII command per line, one JSON reply per line.
 *   ping | state | snapshot
 *   key <idx> <0|1> | press <idx> [ms] | rotate <clicks>
 *   weight <grams> | led <name> <value> | backlight <value>
 *   exec <shell command> | reboot | poweroff
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define VG_DIR "/tmp/vg"
#define KEYS_FILE VG_DIR "/keys"
#define WEIGHT_FILE VG_DIR "/weight"
#define HW_FILE VG_DIR "/hw"
#define STATE_FILE VG_DIR "/state.json"
#define LOG_FILE VG_DIR "/agent.log"
#define CTRL_CANDIDATES 8

static int g_ctrl = -1;
static int g_seq = 0;
static int g_uinput = -1;
static int g_rotate_fd = -1;
static int g_event_is_fifo = 0;
static int g_json_fd = -1;
static int g_pty_master = -1;
static char g_pty_slave[128];
static int g_tty0_master = -1;

/* Synthetic sensor values. They are read from HW_FILE on every feeder cycle
 * so a test can change them with one guest shell command. All values are
 * millivolts (the vendor current conversion is identity: mV == mA) except
 * the fan RPM. */
static long g_agsa_ma = 120;     /* AgsaMotorPowerVoltageIn */
static long g_ntc1_mv = 1030;    /* Ntc1VoltageIn: 25 C on the HSG divider */
static long g_ntc2_mv = 1030;    /* Ntc2VoltageIn */
static long g_ddd_mv = 1650;     /* DddAnalogVoltageIn, mid-scale angle */
static long g_fan_rpm = 0;       /* fan tacho override; 0 = derive from PWM */

/* ------------------------------------------------------------------ util */

static void vglog(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(buf) - 1) n = sizeof(buf) - 1;
    int fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { (void)!write(fd, buf, (size_t)n); (void)!write(fd, "\n", 1); close(fd); }
    fd = open("/dev/console", O_WRONLY | O_NOCTTY);
    if (fd >= 0) { (void)!write(fd, "vg-agent: ", 10); (void)!write(fd, buf, (size_t)n); (void)!write(fd, "\n", 1); close(fd); }
}

static int mkdir_p(const char *path, mode_t mode) {
    char tmp[512];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return -1;
    memcpy(tmp, path, len + 1);
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t n = strlen(data);
    ssize_t w = write(fd, data, n);
    close(fd);
    return w == (ssize_t)n ? 0 : -1;
}

static int read_file(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return (int)n;
}

static void json_escape(const char *in, char *out, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') { out[j++] = '\\'; out[j++] = (char)c; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (c == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else if (c < 0x20) { j += (size_t)snprintf(out + j, cap - j, "\\u%04x", c); }
        else out[j++] = (char)c;
    }
    out[j] = 0;
}

/* ------------------------------------------------------- sysfs overlays */

struct overlay {
    const char *path;
    int mounted;
};

static struct overlay g_overlays[] = {
    {"/sys/class/input", 0},
    {"/sys/class/leds", 0},
    {"/sys/class/backlight", 0},
    {"/sys/class/gpio", 0},
    {"/sys/bus/iio/devices", 0},
    {"/sys/bus/platform/drivers", 0},
    {"/sys/bus/platform/devices", 0},
    {"/sys/bus/nvmem/devices", 0},
    {"/sys/devices/platform", 0},
};

static void mount_overlay(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        vglog("overlay skip (missing): %s", path);
        return;
    }
    if (mount("tmpfs", path, "tmpfs", 0, "mode=755,size=2m") != 0) {
        vglog("overlay failed: %s: %s", path, strerror(errno));
        return;
    }
    for (size_t i = 0; i < sizeof(g_overlays) / sizeof(g_overlays[0]); i++) {
        if (strcmp(g_overlays[i].path, path) == 0) g_overlays[i].mounted = 1;
    }
    vglog("overlay mounted: %s", path);
}

static const char *const LEDS[] = {
    "AGSA_DRV_PHASE", "AGSA_DRV_MODE1", "AGSA_DRV_MODE2", "AGSA_DRV_nSLEEP",
    "AGSA_EN", "FAN1_EN", "FAN2_EN", "USB_EN", NULL
};


static long read_weight(void);

/* The vendor computes grind weight as  weight = C0 + C1 * raw  with the
 * calibration constants from /db/HsgConfig.json (gbwAdcToWeightC0/C1). The
 * fixture must invert that, otherwise an idle machine reports ~2883 g.
 * The factory values are the fallback when the database is missing. */
#define LOADCELL_C0_FALLBACK 2974.494926
#define LOADCELL_C1_FALLBACK -0.091416034
static double g_loadcell_c0 = LOADCELL_C0_FALLBACK;
static double g_loadcell_c1 = LOADCELL_C1_FALLBACK;

static double config_number(const char *key, double fallback)
{
    static char buf[65536];
    int fd = open("/db/HsgConfig.json", O_RDONLY);
    if (fd < 0) return fallback;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return fallback;
    buf[n] = 0;
    char needle[96];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    char *p = strstr(buf, needle);
    if (!p) return fallback;
    p = strchr(p + strlen(needle), ':');
    if (!p) return fallback;
    char *end = NULL;
    double v = strtod(p + 1, &end);
    return end == p + 1 ? fallback : v;
}

static void load_loadcell_calibration(void)
{
    g_loadcell_c0 = config_number("gbwAdcToWeightC0", LOADCELL_C0_FALLBACK);
    g_loadcell_c1 = config_number("gbwAdcToWeightC1", LOADCELL_C1_FALLBACK);
    vglog("loadcell calibration C0=%.6f C1=%.9f", g_loadcell_c0, g_loadcell_c1);
}

static unsigned loadcell_raw_for(long grams)
{
    double w = (double)grams;
    if (g_loadcell_c1 > -1e-12 && g_loadcell_c1 < 1e-12) return 1000;
    double raw = (w - g_loadcell_c0) / g_loadcell_c1;
    if (raw < 0.0) raw = 0.0;
    if (raw > 65535.0) raw = 65535.0;
    return (unsigned)(raw + 0.5);
}

static void update_loadcell_raw(unsigned raw)
{
    static unsigned last = 0xffffffffu;
    char v[16];
    char p[256];
    if (raw == last) return;
    last = raw;
    snprintf(v, sizeof(v), "%u\n", raw);
    for (int ch = 0; ch <= 12; ch++) {
        snprintf(p, sizeof(p),
                 "/sys/bus/platform/devices/48003000.adc:adc@0/iio:device3/in_voltage%d_raw", ch);
        write_file(p, v);
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device3/in_voltage%d_raw", ch);
        write_file(p, v);
    }
    write_file("/tmp/vg/loadcell_raw", v);
}

static void load_hw(void)
{
    char buf[512];
    if (read_file(HW_FILE, buf, sizeof(buf)) <= 0) return;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char key[32];
        long value;
        if (sscanf(line, "%31s %ld", key, &value) != 2) continue;
        if (!strcmp(key, "agsa_ma")) g_agsa_ma = value;
        else if (!strcmp(key, "ntc1_mv")) g_ntc1_mv = value;
        else if (!strcmp(key, "ntc2_mv")) g_ntc2_mv = value;
        else if (!strcmp(key, "ddd_mv")) g_ddd_mv = value;
        else if (!strcmp(key, "fan_rpm")) g_fan_rpm = value;
    }
}

static void write_hw_file(void)
{
    char buf[256];
    snprintf(buf, sizeof(buf),
             "agsa_ma %ld\nntc1_mv %ld\nntc2_mv %ld\nddd_mv %ld\nfan_rpm %ld\n",
             g_agsa_ma, g_ntc1_mv, g_ntc2_mv, g_ddd_mv, g_fan_rpm);
    write_file(HW_FILE, buf);
}

/* Keep the polled AdcVoltageInDriver fixtures in sync with /tmp/vg/hw. */
static void refresh_platform_adc(void)
{
    char p[256], v[16];
    const struct { int ch; long mv; } vals[] = {
        {9, g_ntc2_mv}, {10, g_agsa_ma}, {11, g_ddd_mv}, {12, g_ntc1_mv},
    };
    for (unsigned i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        snprintf(v, sizeof(v), "%ld\n", vals[i].mv);
        snprintf(p, sizeof(p),
                 "/sys/bus/platform/devices/48003000.adc:adc@100/iio:device4/in_voltage%d_raw",
                 vals[i].ch);
        write_file(p, v);
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device4/in_voltage%d_raw", vals[i].ch);
        write_file(p, v);
    }
}

static void *hw_refresh_thread(void *arg)
{
    (void)arg;
    for (;;) {
        load_hw();
        refresh_platform_adc();
        struct timespec ts = {0, 500 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static int set_hw(const char *key, long value)
{
    if (!strcmp(key, "agsa_ma")) g_agsa_ma = value;
    else if (!strcmp(key, "ntc1_mv")) g_ntc1_mv = value;
    else if (!strcmp(key, "ntc2_mv")) g_ntc2_mv = value;
    else if (!strcmp(key, "ddd_mv")) g_ddd_mv = value;
    else if (!strcmp(key, "fan_rpm")) g_fan_rpm = value;
    else return -1;
    write_hw_file();
    return 0;
}

typedef struct { int device; int kind; } AdcFeederArg;

/* kind 0: load cell (ADC1 / ADC2 load-cell device)
 * kind 1: DDD analogue, constant
 * kind 2: ADC2 voltage-in bank: even samples = AGSA current, odd = NTC
 *
 * The demuxer assigns samples to channel slots round-robin and the reader
 * consumes 90 uint16 per read. 90 is even, so this two-value pattern gives
 * every slot a stable value across reads. */
static void *adc_feeder(void *opaque)
{
    AdcFeederArg *arg = (AdcFeederArg *)opaque;
    char path[64];
    snprintf(path, sizeof(path), "/dev/iio:device%d", arg->device);
    int fd = open(path, O_RDWR | O_NONBLOCK);
    if (fd < 0) return NULL;
    unsigned char frame[180];
    unsigned long ticks = 0;
    for (;;) {
        if ((ticks++ % 10) == 0) load_hw();
        unsigned sample[90];
        if (arg->kind == 0) {
            unsigned raw = loadcell_raw_for(read_weight());
            update_loadcell_raw(raw);
            for (int i = 0; i < 90; i++) sample[i] = raw;
        } else if (arg->kind == 1) {
            for (int i = 0; i < 90; i++) sample[i] = (unsigned)g_ddd_mv;
        } else if (arg->kind == 3) {
            /* ADC2 scan order used by S52adc2: in_voltage2, 9, 10, 12.
             * Map slot 0..3 to the four voltage-in drivers. */
            unsigned pat[4] = {
                (unsigned)g_ntc2_mv, (unsigned)g_agsa_ma,
                (unsigned)g_ddd_mv, (unsigned)g_ntc1_mv,
            };
            for (int i = 0; i < 90; i++) sample[i] = pat[i & 3];
        } else {
            for (int i = 0; i < 90; i++)
                sample[i] = (i & 1) ? (unsigned)g_ntc1_mv : (unsigned)g_agsa_ma;
        }
        for (int i = 0; i < 90; i++) {
            frame[i * 2] = sample[i] & 0xff;
            frame[i * 2 + 1] = (sample[i] >> 8) & 0xff;
        }
        ssize_t n = write(fd, frame, sizeof(frame));
        if (n < 0 && errno != EAGAIN && errno != EPIPE) {
            close(fd);
            fd = open(path, O_RDWR | O_NONBLOCK);
            if (fd < 0) return NULL;
        }
        struct timespec ts = {0, 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
}

static void start_adc_feeders(void)
{
    static AdcFeederArg args[] = {
        {3, 0}, {4, 3}, {5, 2}, {6, 2},
    };
    for (unsigned i = 0; i < sizeof(args) / sizeof(args[0]); i++) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, adc_feeder, &args[i]) == 0)
            pthread_detach(thread);
    }
}

/* Fan tachometer. The vendor PwmCaptureDriver polls <pwmchip>/pwmN/capture
 * and expects "<period_ns> <duty_ns>". The capture path is built from the
 * timer base in NgxUiApp (0x40002000/chip0/pwm1 for fan1,
 * 0x40003000/chip4/pwm3 for fan2). RPM = round(hz * 30); the vendor fan curve
 * is rpm = 780 + 45.2 * duty_percent. Deriving the tacho from the PWM duty
 * closes that loop, so CalibrateFan1/2 steps through 1..100 % instead of
 * waiting forever for a tacho that a real fan would provide. */
struct fan_loop {
    const char *pwm_dir;     /* period + duty_cycle written by PwmOutDriver */
    const char *capture;     /* primary capture file the HMI polls */
};

static const struct fan_loop FAN_LOOPS[] = {
    {"/sys/devices/platform/soc/40006000.timer/40006000.timer:pwm/pwm/pwmchip0/pwm8",
     "/sys/devices/platform/soc/40002000.timer/40002000.timer:pwm/pwm/pwmchip0/pwm2/capture"},
    {"/sys/devices/platform/soc/40007000.timer/40007000.timer:pwm/pwm/pwmchip0/pwm10",
     "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip4/pwm3/capture"},
};

/* Alternate capture paths kept in sync for board revisions whose timer
 * assignment differs; only the path the vendor binary builds is read. */
static const char *const CAPTURE_FILES[] = {
    "/sys/devices/platform/soc/40002000.timer/40002000.timer:pwm/pwm/pwmchip0/pwm1/capture",
    "/sys/devices/platform/soc/40002000.timer/40002000.timer:pwm/pwm/pwmchip0/pwm2/capture",
    "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip4/pwm3/capture",
    "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip1/pwm3/capture",
    "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip0/pwm3/capture",
    "/sys/devices/platform/soc/44000000.timer/44000000.timer:pwm/pwm/pwmchip4/pwm3/capture",
    NULL
};

static long read_long_file(const char *path)
{
    char b[64];
    if (read_file(path, b, sizeof(b)) <= 0) return -1;
    return strtol(b, NULL, 10);
}

static void *fan_feeder(void *opaque)
{
    (void)opaque;
    for (;;) {
        load_hw();
        long rpm = g_fan_rpm;
        if (rpm <= 0) {
            /* Derive from the highest active fan PWM. During calibration only
             * one fan is driven, so the maximum is the fan under test. */
            double best_rpm = 0.0;
            for (unsigned i = 0; i < sizeof(FAN_LOOPS) / sizeof(FAN_LOOPS[0]); i++) {
                char p[256];
                long period, duty;
                snprintf(p, sizeof(p), "%s/period", FAN_LOOPS[i].pwm_dir);
                period = read_long_file(p);
                snprintf(p, sizeof(p), "%s/duty_cycle", FAN_LOOPS[i].pwm_dir);
                duty = read_long_file(p);
                if (period > 0 && duty > 0) {
                    double pct = (double)duty * 100.0 / (double)period;
                    double r = 780.0 + 45.2 * pct;
                    if (r > best_rpm) best_rpm = r;
                }
            }
            rpm = (long)(best_rpm + 0.5);
        }
        char value[64];
        if (rpm <= 0) {
            snprintf(value, sizeof(value), "0 0\n");
        } else {
            /* rpm = hz * 30  ->  period_ns = 30e9 / rpm */
            unsigned long period = (unsigned long)(30000000000.0 / (double)rpm);
            if (period == 0) period = 1;
            snprintf(value, sizeof(value), "%lu %lu\n", period, period / 2);
        }
        for (int i = 0; CAPTURE_FILES[i]; i++) write_file(CAPTURE_FILES[i], value);
        struct timespec ts = {0, 100 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static void start_fan_feeder(void)
{
    /* Create the PWM output and capture trees before the HMI starts. */
    for (unsigned i = 0; i < sizeof(FAN_LOOPS) / sizeof(FAN_LOOPS[0]); i++) {
        char p[256];
        mkdir_p(FAN_LOOPS[i].pwm_dir, 0755);
        snprintf(p, sizeof(p), "%s/period", FAN_LOOPS[i].pwm_dir);
        if (access(p, F_OK) != 0) write_file(p, "40000\n");
        snprintf(p, sizeof(p), "%s/duty_cycle", FAN_LOOPS[i].pwm_dir);
        if (access(p, F_OK) != 0) write_file(p, "0\n");
        snprintf(p, sizeof(p), "%s/enable", FAN_LOOPS[i].pwm_dir);
        if (access(p, F_OK) != 0) write_file(p, "0\n");
        write_file(FAN_LOOPS[i].capture, "0 0\n");
    }
    for (int i = 0; CAPTURE_FILES[i]; i++) {
        if (access(CAPTURE_FILES[i], F_OK) != 0) write_file(CAPTURE_FILES[i], "0 0\n");
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, fan_feeder, NULL) == 0) pthread_detach(thread);
}

static void seed_sysfs(void) {
    char p[512];

    /* gpio-keys vendor attribute: the HMI writes an index then reads 0/1.
     * The real semantics are provided by the LD_PRELOAD shim; this plain file
     * covers tools (cat/echo) that do not run with the preload. */
    mkdir_p("/sys/class/input/input1/device", 0755);
    write_file("/sys/class/input/input1/device/gpio_value", "0\n");
    mkdir_p("/sys/class/input/input1", 0755);
    write_file("/sys/class/input/input1/name", "vg-keys\n");

    for (int i = 0; LEDS[i]; i++) {
        snprintf(p, sizeof(p), "/sys/class/leds/%s", LEDS[i]);
        mkdir_p(p, 0755);
        snprintf(p, sizeof(p), "/sys/class/leds/%s/brightness", LEDS[i]);
        write_file(p, "0\n");
        snprintf(p, sizeof(p), "/sys/class/leds/%s/max_brightness", LEDS[i]);
        write_file(p, "1\n");
    }

    mkdir_p("/sys/class/backlight/backlight", 0755);
    write_file("/sys/class/backlight/backlight/brightness", "128\n");
    write_file("/sys/class/backlight/backlight/max_brightness", "255\n");
    write_file("/sys/class/backlight/backlight/bl_power", "0\n");

    write_file("/sys/class/gpio/export", "");
    write_file("/sys/class/gpio/unexport", "");
    for (int g = 59; g <= 61; g++) {
        snprintf(p, sizeof(p), "/sys/class/gpio/gpio%d", g);
        mkdir_p(p, 0755);
        write_file("/sys/class/gpio/gpio59/direction", "out\n");
        write_file("/sys/class/gpio/gpio60/direction", "out\n");
        write_file("/sys/class/gpio/gpio61/direction", "out\n");
        snprintf(p, sizeof(p), "/sys/class/gpio/gpio%d/value", g);
        write_file(p, "0\n");
    }

    /* IIO: five devices. The app hardcodes iio:device3..6. The char nodes in
     * /dev stay regular files (samples are not emulated; see README). */
    for (int d = 3; d <= 6; d++) {
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d", d);
        mkdir_p(p, 0755);
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/name", d);
        write_file(p, d == 3 ? "48003000.adc:adc@0\n" : "48003000.adc:adc@100\n");
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/buffer", d);
        mkdir_p(p, 0755);
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/buffer/enable", d);
        write_file(p, "0\n");
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/buffer/length", d);
        write_file(p, "580\n");
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/buffer/watermark", d);
        write_file(p, "290\n");
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/trigger", d);
        mkdir_p(p, 0755);
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/trigger/current_trigger", d);
        write_file(p, "tim6_trgo\n");
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/scan_elements", d);
        mkdir_p(p, 0755);
        for (int ch = 0; ch <= 12; ch++) {
            snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/scan_elements/in_voltage%d_en", d, ch);
            write_file(p, "0\n");
            snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/scan_elements/in_voltage%d-voltage%d_en", d, ch, ch);
            write_file(p, "0\n");
            /* Mirror the platform-device fixture so both sysfs views agree. */
            unsigned mv = 1650;
            if (d == 4) {
                /* NgxUiApp HSG wiring: ch9 Ntc2, ch10 AgsaMotorPower,
                 * ch11 DddAnalog, ch12 Ntc1. */
                if (ch == 9) mv = (unsigned)g_ntc2_mv;
                else if (ch == 10) mv = (unsigned)g_agsa_ma;
                else if (ch == 11) mv = (unsigned)g_ddd_mv;
                else if (ch == 12) mv = (unsigned)g_ntc1_mv;
            }
            snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/in_voltage%d_raw", d, ch);
            char v[16];
            snprintf(v, sizeof(v), "%u\n", d == 3 ? loadcell_raw_for(read_weight()) : mv);
            write_file(p, v);
        }
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/in_voltage_scale", d);
        write_file(p, "1.0\n");
        snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/in_voltage_offset", d);
        write_file(p, "0\n");
    }

    /* The HMI resolves the voltage-in drivers through the platform-device
     * path, not /sys/bus/iio. The vendor driver appends "/in_voltage%1_raw"
     * to this directory (evidence: NgxUiApp iio:device4 + channel strings,
     * libNgxUi.so 0x2102f0). Every channel the HMI can poll must exist here. */
    const char *plat[][2] = {
        {"/sys/bus/platform/devices/48003000.adc:adc@0/iio:device3", "48003000.adc:adc@0"},
        {"/sys/bus/platform/devices/48003000.adc:adc@100/iio:device4", "48003000.adc:adc@100"},
        {"/sys/bus/platform/devices/48003000.adc:adc@100/iio:device5", "48003000.adc:adc@100"},
        {"/sys/bus/platform/devices/48003000.adc:adc@100/iio:device6", "48003000.adc:adc@100"},
    };
    for (unsigned k = 0; k < sizeof(plat) / sizeof(plat[0]); k++) {
        const char *dir = plat[k][0];
        mkdir_p(dir, 0755);
        snprintf(p, sizeof(p), "%s/name", dir);
        write_file(p, plat[k][1]);
        snprintf(p, sizeof(p), "%s/buffer", dir);
        mkdir_p(p, 0755);
        snprintf(p, sizeof(p), "%s/buffer/enable", dir);
        write_file(p, "0\n");
        snprintf(p, sizeof(p), "%s/buffer/length", dir);
        write_file(p, "580\n");
        snprintf(p, sizeof(p), "%s/buffer/watermark", dir);
        write_file(p, "290\n");
        snprintf(p, sizeof(p), "%s/trigger", dir);
        mkdir_p(p, 0755);
        snprintf(p, sizeof(p), "%s/trigger/current_trigger", dir);
        write_file(p, "tim6_trgo\n");
        snprintf(p, sizeof(p), "%s/scan_elements", dir);
        mkdir_p(p, 0755);
        for (int ch = 0; ch <= 12; ch++) {
            unsigned mv = 1650;
            if (strstr(dir, "iio:device4")) {
                /* HSG ADC2 binding from NgxUiApp create() call sites:
                 * ch9 Ntc2, ch10 DddAnalog, ch11 AgsaMotorPower, ch12 Ntc1. */
                /* NgxUiApp HSG wiring: ch9 Ntc2, ch10 AgsaMotorPower,
                 * ch11 DddAnalog, ch12 Ntc1. */
                if (ch == 9) mv = (unsigned)g_ntc2_mv;
                else if (ch == 10) mv = (unsigned)g_agsa_ma;
                else if (ch == 11) mv = (unsigned)g_ddd_mv;
                else if (ch == 12) mv = (unsigned)g_ntc1_mv;
            }
            snprintf(p, sizeof(p), "%s/in_voltage%d_en", dir, ch);
            write_file(p, "0\n");
            snprintf(p, sizeof(p), "%s/in_voltage%d-voltage%d_en", dir, ch, ch);
            write_file(p, "0\n");
            snprintf(p, sizeof(p), "%s/in_voltage%d_raw", dir, ch);
            char v[16];
            snprintf(v, sizeof(v), "%u\n", mv);
            write_file(p, v);
        }
        snprintf(p, sizeof(p), "%s/in_voltage_scale", dir);
        write_file(p, "1.0\n");
        snprintf(p, sizeof(p), "%s/in_voltage_offset", dir);
        write_file(p, "0\n");
    }

    /* STM32 timers / one-pulse / PWM: inert files, values observable. */
    mkdir_p("/sys/bus/platform/drivers/stm32-one-pulse/40000000.timer:op", 0755);
    write_file("/sys/bus/platform/drivers/stm32-one-pulse/40000000.timer:op/prepare", "0\n");
    write_file("/sys/bus/platform/drivers/stm32-one-pulse/40000000.timer:op/disable", "0\n");
    write_file("/sys/bus/platform/drivers/stm32-one-pulse/40000000.timer:op/pulse_length", "0\n");
    mkdir_p("/sys/bus/platform/drivers/stm32-one-pulse/44006000.timer:op", 0755);
    write_file("/sys/bus/platform/drivers/stm32-one-pulse/44006000.timer:op/prepare", "0\n");
    write_file("/sys/bus/platform/drivers/stm32-one-pulse/44006000.timer:op/disable", "0\n");
    mkdir_p("/sys/bus/platform/drivers/stm32-timers/40001000.timer/40001000.timer:counter/counter0", 0755);
    write_file("/sys/bus/platform/drivers/stm32-timers/40001000.timer/40001000.timer:counter/counter0/count0", "0\n");
    write_file("/sys/bus/platform/drivers/stm32-timers/40001000.timer/40001000.timer:counter/counter0/enable", "0\n");
    mkdir_p("/sys/bus/platform/drivers/stm32-timers/44001000.timer/44001000.timer:counter/counter2", 0755);
    write_file("/sys/bus/platform/drivers/stm32-timers/44001000.timer/44001000.timer:counter/counter2/count0", "0\n");
    mkdir_p("/sys/devices/platform/soc/40000000.timer", 0755);
    mkdir_p("/sys/devices/platform/soc/40000000.timer/40000000.timer:counter/counter0", 0755);
    mkdir_p("/sys/devices/platform/soc/40000000.timer/40000000.timer:pwm/pwm/pwmchip0", 0755);
    mkdir_p("/sys/devices/platform/soc/44001000.timer", 0755);
    mkdir_p("/sys/devices/platform/soc/44001000.timer/44001000.timer:counter/counter2", 0755);

    /* timer_setup.sh and S52adc2 cd into counterX/count0 of TIM3 (40001000)
     * and TIM6 (40004000). Both were missing, so the scripts printed
     * "can't cd to ..." before their arithmetic error. */
    const char *const TIMER_COUNTERS[] = {
        "/sys/devices/platform/soc/40001000.timer/40001000.timer:counter/counter0",
        "/sys/devices/platform/soc/40004000.timer/40004000.timer:counter/counter0",
        "/sys/devices/platform/soc/40000000.timer/40000000.timer:counter/counter0",
    };
    for (unsigned t = 0; t < sizeof(TIMER_COUNTERS) / sizeof(TIMER_COUNTERS[0]); t++) {
        char c0[320];
        mkdir_p(TIMER_COUNTERS[t], 0755);
        /* The vendor scripts cd into counterX/count0 and then write
         * enable/function; count0 itself must be a directory. */
        snprintf(c0, sizeof(c0), "%s/count0", TIMER_COUNTERS[t]);
        mkdir_p(c0, 0755);
        snprintf(p, sizeof(p), "%s/count", c0);
        write_file(p, "0\n");
        snprintf(p, sizeof(p), "%s/enable", c0);
        write_file(p, "0\n");
        snprintf(p, sizeof(p), "%s/function", c0);
        write_file(p, "0\n");
    }

    /* DddPwmCapture (NgxUiApp 0x13d54) is built from timer 44001000 and a
     * pwmchip/pwm pair. Create the plausible (chip, channel) combinations so
     * the attribute exists; a real A1330 outputs a 1 kHz PWM whose duty
     * encodes the disc angle, so seed a valid mid-scale capture value. */
    {
        const int chips[] = {14, 0};
        for (unsigned ci = 0; ci < sizeof(chips) / sizeof(chips[0]); ci++) {
            char dir[320];
            snprintf(dir, sizeof(dir),
                     "/sys/devices/platform/soc/44001000.timer/44001000.timer:pwm/pwm/pwmchip%d",
                     chips[ci]);
            mkdir_p(dir, 0755);
            snprintf(p, sizeof(p), "%s/export", dir);
            write_file(p, "0\n");
            for (int ch = 0; ch <= 3; ch++) {
                snprintf(p, sizeof(p), "%s/pwm%d", dir, ch);
                mkdir_p(p, 0755);
                snprintf(p, sizeof(p), "%s/pwm%d/capture", dir, ch);
                write_file(p, "1000000 500000\n");
                snprintf(p, sizeof(p), "%s/pwm%d/period", dir, ch);
                write_file(p, "1000000\n");
                snprintf(p, sizeof(p), "%s/pwm%d/duty_cycle", dir, ch);
                write_file(p, "500000\n");
                snprintf(p, sizeof(p), "%s/pwm%d/enable", dir, ch);
                write_file(p, "1\n");
            }
        }
    }
    /* Paths the AGSA/PWM drivers poll continuously (from the live HMI log). */
    mkdir_p("/sys/devices/platform/soc/44001000.timer/44001000.timer:counter/counter2/count0", 0755);
    write_file("/sys/devices/platform/soc/44001000.timer/44001000.timer:counter/counter2/count0/count", "0\n");
    write_file("/sys/devices/platform/soc/44001000.timer/44001000.timer:counter/counter2/count0/enable", "0\n");
    write_file("/sys/devices/platform/soc/44001000.timer/44001000.timer:counter/counter2/count0/function", "0\n");
    mkdir_p("/sys/devices/platform/soc/40002000.timer/40002000.timer:pwm/pwm/pwmchip0/pwm2", 0755);
    write_file("/sys/devices/platform/soc/40002000.timer/40002000.timer:pwm/pwm/pwmchip0/export", "0\n");
    write_file("/sys/devices/platform/soc/40002000.timer/40002000.timer:pwm/pwm/pwmchip0/pwm2/capture", "0 0\n");
    write_file("/sys/devices/platform/soc/40002000.timer/40002000.timer:pwm/pwm/pwmchip0/pwm2/period", "0\n");
    write_file("/sys/devices/platform/soc/40002000.timer/40002000.timer:pwm/pwm/pwmchip0/pwm2/duty_cycle", "0\n");
    write_file("/sys/devices/platform/soc/40002000.timer/40002000.timer:pwm/pwm/pwmchip0/pwm2/enable", "0\n");
    /* fan2 uses timer 40003000 (NgxUiApp 0xeac0/0xec60). Create both a
     * pwmchip0 and a pwmchip1 variant; only the path the driver builds is
     * read, the other one is inert. */
    for (int chip = 0; chip <= 1; chip++) {
        snprintf(p, sizeof(p),
                 "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip%d/pwm3",
                 chip);
        mkdir_p(p, 0755);
        snprintf(p, sizeof(p),
                 "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip%d/export",
                 chip);
        write_file(p, "0\n");
        snprintf(p, sizeof(p),
                 "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip%d/pwm3/capture",
                 chip);
        write_file(p, "0 0\n");
        snprintf(p, sizeof(p),
                 "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip%d/pwm3/period",
                 chip);
        write_file(p, "0\n");
        snprintf(p, sizeof(p),
                 "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip%d/pwm3/duty_cycle",
                 chip);
        write_file(p, "0\n");
        snprintf(p, sizeof(p),
                 "/sys/devices/platform/soc/40003000.timer/40003000.timer:pwm/pwm/pwmchip%d/pwm3/enable",
                 chip);
        write_file(p, "0\n");
    }
    mkdir_p("/sys/devices/platform/soc/44000000.timer/44000000.timer:pwm/pwm/pwmchip4/pwm3", 0755);
    write_file("/sys/devices/platform/soc/44000000.timer/44000000.timer:pwm/pwm/pwmchip4/export", "0\n");
    write_file("/sys/devices/platform/soc/44000000.timer/44000000.timer:pwm/pwm/pwmchip4/pwm3/period", "0\n");
    write_file("/sys/devices/platform/soc/44000000.timer/44000000.timer:pwm/pwm/pwmchip4/pwm3/duty_cycle", "0\n");
    write_file("/sys/devices/platform/soc/44000000.timer/44000000.timer:pwm/pwm/pwmchip4/pwm3/enable", "0\n");
    write_file("/sys/devices/platform/soc/44000000.timer/44000000.timer:pwm/pwm/pwmchip4/pwm3/capture", "0 0\n");

    /* ADC2 scale/offset used by GrindController calibration. */
    mkdir_p("/sys/bus/platform/devices/48003000.adc:adc@100/iio:device4", 0755);
    write_file("/sys/bus/platform/devices/48003000.adc:adc@100/iio:device4/in_voltage_scale", "1.0\n");
    write_file("/sys/bus/platform/devices/48003000.adc:adc@100/iio:device4/in_voltage_offset", "0\n");

    /* BSEC OTP window used by CpuTempDriver (dd skip=23 bs=4 count=1). */
    mkdir_p("/sys/bus/nvmem/devices/stm32-romem0", 0755);
    unsigned char otp[128];
    memset(otp, 0, sizeof(otp));
    /* two plausible TS_CAL half-words at word 23 */
    otp[92] = 0x50; otp[93] = 0x06; otp[94] = 0x90; otp[95] = 0x06;
    int fd = open("/sys/bus/nvmem/devices/stm32-romem0/nvmem", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { (void)!write(fd, otp, sizeof(otp)); close(fd); }

    /* /dev nodes the HMI opens directly. */
    mkdir_p("/dev/input", 0755);
    if (access("/dev/watchdog", F_OK) != 0) {
        fd = open("/dev/watchdog", O_WRONLY | O_CREAT, 0644);
        if (fd >= 0) { (void)!write(fd, "V", 1); close(fd); }
    }
    for (int d = 3; d <= 6; d++) {
        snprintf(p, sizeof(p), "/dev/iio:device%d", d);
        unlink(p);
        /* A FIFO, not an empty file: AdcDmaReader opens it and reads
         * 180-byte frames of 90 uint16 samples. */
        (void)mkfifo(p, 0666);
    }
    start_adc_feeders();
    start_fan_feeder();
    /* WiFi netdev names used by EspWifiConfig; dummy module makes them real. */
    (void)!system("ip link add ethsta0 type dummy 2>/dev/null; ip link set ethsta0 up 2>/dev/null;"
                  "ip link add ethap0 type dummy 2>/dev/null; ip link set ethap0 up 2>/dev/null;"
                  "ip addr add 192.168.7.50/24 dev ethsta0 2>/dev/null");
}

/* --------------------------------------------------------------- uinput */

static int setup_uinput(void) {
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    /* Returns the uinput fd on success: events are injected by writing
     * struct input_event records to it, not to the evdev node. */
    if (fd < 0) {
        vglog("uinput open failed: %s", strerror(errno));
        return -1;
    }
    if (ioctl(fd, UI_SET_EVBIT, EV_REL) != 0) { vglog("UI_SET_EVBIT: %s", strerror(errno)); close(fd); return -1; }
    ioctl(fd, UI_SET_RELBIT, REL_DIAL);
    ioctl(fd, UI_SET_RELBIT, REL_X);
    /* The devicetree gpio-keys node uses codes 2..8 for the front-panel
     * keys; expose the same codes on the virtual input device. */
    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    for (int code = 2; code <= 8; code++) ioctl(fd, UI_SET_KEYBIT, code);

    struct uinput_user_dev udev;
    memset(&udev, 0, sizeof(udev));
    snprintf(udev.name, sizeof(udev.name), "vg-rotary");
    udev.id.bustype = BUS_VIRTUAL;
    udev.id.vendor = 0x5647;
    udev.id.product = 0x0001;
    udev.id.version = 1;
    if (write(fd, &udev, sizeof(udev)) != (ssize_t)sizeof(udev)) {
        vglog("uinput write: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (ioctl(fd, UI_DEV_CREATE) != 0) {
        vglog("UI_DEV_CREATE: %s", strerror(errno));
        close(fd);
        return -1;
    }
    /* Give devtmpfs/udev a moment, then find our device by its evdev name.
     * /sys/class/input is masked by the agent's own tmpfs overlay, so use
     * EVIOCGNAME on the /dev nodes instead. udev also cannot create the node
     * once /sys/class/input is masked, so create event0..7 ourselves. */
    for (int n = 0; n < 8; n++) {
        char node[64];
        snprintf(node, sizeof(node), "/dev/input/event%d", n);
        if (access(node, F_OK) != 0) {
            (void)mknod(node, S_IFCHR | 0666, makedev(13, 64 + n));
        }
    }
    for (int i = 0; i < 100; i++) {
        for (int n = 0; n < 8; n++) {
            char node[64], name[64] = "";
            snprintf(node, sizeof(node), "/dev/input/event%d", n);
            int fd2 = open(node, O_RDONLY | O_NONBLOCK);
            if (fd2 < 0) continue;
            if (ioctl(fd2, EVIOCGNAME(sizeof(name)), name) > 0) {
                close(fd2);
                if (!strcmp(name, "vg-rotary")) {
                    if (n != 0) {
                        unlink("/dev/input/event0");
                        if (symlink(node, "/dev/input/event0") != 0) {
                            vglog("symlink %s -> event0 failed: %s", node, strerror(errno));
                        }
                    }
                    vglog("uinput created %s (event0 -> %s)", node, node);
                    return fd;
                }
            } else {
                close(fd2);
            }
        }
        usleep(50000);
    }
    vglog("uinput device did not appear");
    /* Keep the fd open: closing it would destroy the input device. */
    return -1;
}

static int setup_rotary_fifo(void) {    /* Fallback when uinput is unavailable: the HMI only read()s 16-byte
     * input_event records, so a FIFO fed by this agent is sufficient. */
    unlink("/dev/input/event0");
    if (mkfifo("/dev/input/event0", 0666) != 0) {
        vglog("mkfifo event0: %s", strerror(errno));
        return -1;
    }
    g_rotate_fd = open("/dev/input/event0", O_RDWR | O_NONBLOCK);
    if (g_rotate_fd < 0) {
        vglog("open event0 fifo: %s", strerror(errno));
        return -1;
    }
    g_event_is_fifo = 1;
    vglog("rotary FIFO fallback active at /dev/input/event0");
    return 0;
}

static int emit_rotary(int clicks) {
    /* Layout of struct input_event on 32-bit ARM/glibc:
     * timeval(8) + u16 type + u16 code + s32 value = 16 bytes. */
    struct {
        uint32_t sec;
        uint32_t usec;
        uint16_t type;
        uint16_t code;
        int32_t value;
    } ev;
    memset(&ev, 0, sizeof(ev));
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ev.sec = (uint32_t)ts.tv_sec;
    ev.usec = (uint32_t)(ts.tv_nsec / 1000);
    ev.type = EV_REL;
    ev.code = REL_DIAL;
    ev.value = clicks;
    if (g_event_is_fifo) {
        if (g_rotate_fd < 0) return -1;
        return write(g_rotate_fd, &ev, sizeof(ev)) == (ssize_t)sizeof(ev) ? 0 : -1;
    }
    if (g_uinput < 0) return -1;
    ssize_t n = write(g_uinput, &ev, sizeof(ev));
    if (n != (ssize_t)sizeof(ev)) {
        vglog("emit_rotary write=%zd errno=%s", n, strerror(errno));
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------- tty relay */

static void write_all(int fd, const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) return;
        off += (size_t)n;
    }
}

static void *json_relay(void *arg) {
    (void)arg;
    unsigned char buf[1024];
    for (;;) {
        struct pollfd fds[2];
        fds[0].fd = g_pty_master; fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = g_json_fd;    fds[1].events = POLLIN; fds[1].revents = 0;
        int rc = poll(fds, 2, 500);
        if (rc <= 0) continue;
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(g_pty_master, buf, sizeof(buf));
            if (n > 0) write_all(g_json_fd, buf, (size_t)n);
        }
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(g_json_fd, buf, sizeof(buf));
            if (n > 0) write_all(g_pty_master, buf, (size_t)n);
        }
    }
    return NULL;
}

/* QSerialPort requires a real tty (termios). Virtio-console ports are char
 * devices without termios, so create a guest pty and relay it to the JSON
 * virtio port. The HMI then opens /dev/ttySTM1 -> /dev/pts/N. */
static int setup_tty_relay(void) {
    g_json_fd = open("/dev/vport0p2", O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (g_json_fd < 0) {
        vglog("json port open failed: %s", strerror(errno));
        return -1;
    }
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
        vglog("pty setup failed: %s", strerror(errno));
        if (master >= 0) close(master);
        return -1;
    }
    const char *slave = ptsname(master);
    if (!slave) {
        vglog("ptsname failed");
        close(master);
        return -1;
    }
    snprintf(g_pty_slave, sizeof(g_pty_slave), "%s", slave);
    struct termios tio;
    if (tcgetattr(master, &tio) == 0) {
        cfmakeraw(&tio);
        tcsetattr(master, TCSANOW, &tio);
    }
    unlink("/dev/ttySTM1");
    if (symlink(g_pty_slave, "/dev/ttySTM1") != 0) {
        vglog("symlink ttySTM1 failed: %s", strerror(errno));
    }
    g_pty_master = master;
    pthread_t thread;
    if (pthread_create(&thread, NULL, json_relay, NULL) != 0) {
        vglog("json relay thread failed");
        return -1;
    }
    pthread_detach(thread);
    vglog("ttySTM1 -> %s (relayed to /dev/vport0p2)", g_pty_slave);
    return 0;
}

/* /etc/inittab respawns "getty -L ttySTM0". The VM has no STM32 UART4, so
 * getty prints "can't open /dev/ttySTM0" once per second. Give it a pty whose
 * master is never read: getty sets termios and blocks harmlessly. */
static void setup_console_tty(void)
{
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
        vglog("ttySTM0 pty setup failed: %s", strerror(errno));
        if (master >= 0) close(master);
        return;
    }
    const char *slave = ptsname(master);
    if (!slave) {
        vglog("ttySTM0 ptsname failed");
        close(master);
        return;
    }
    struct termios tio;
    if (tcgetattr(master, &tio) == 0) {
        cfmakeraw(&tio);
        tcsetattr(master, TCSANOW, &tio);
    }
    unlink("/dev/ttySTM0");
    if (symlink(slave, "/dev/ttySTM0") != 0)
        vglog("symlink ttySTM0 failed: %s", strerror(errno));
    else
        vglog("ttySTM0 -> %s (getty sink)", slave);
    g_tty0_master = master;   /* keep the pty alive; never read from it */
}

/* ------------------------------------------------------------- controls */

static void keys_read(char out[9]) {
    char buf[32] = {0};
    if (read_file(KEYS_FILE, buf, sizeof(buf)) <= 0) {
        memset(out, '0', 8);
        out[8] = 0;
        return;
    }
    for (int i = 0; i < 8; i++) out[i] = (buf[i] == '1') ? '1' : '0';
    out[8] = 0;
}

static void keys_write(const char *keys) {
    write_file(KEYS_FILE, keys);
}

static void set_key(int idx, int value) {
    if (idx < 0 || idx > 7) return;
    char keys[9];
    keys_read(keys);
    keys[idx] = value ? '1' : '0';
    keys_write(keys);
    /* Also emit an EV_KEY on the virtual input device. The vendor HMI uses
     * both a gpio_value poll (KeyStateDriver) and Qt key events
     * (ButtonDevice); sending both keeps either path working. */
    if (g_uinput >= 0) {
        struct {
            uint32_t sec, usec;
            uint16_t type, code;
            int32_t value;
        } ev;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        memset(&ev, 0, sizeof(ev));
        ev.sec = (uint32_t)ts.tv_sec;
        ev.usec = (uint32_t)(ts.tv_nsec / 1000);
        ev.type = EV_KEY;
        ev.code = (uint16_t)(idx + 2);
        ev.value = value ? 1 : 0;
        if (write(g_uinput, &ev, sizeof(ev)) != (ssize_t)sizeof(ev))
            vglog("emit_key write failed: %s", strerror(errno));
        memset(&ev, 0, sizeof(ev));
        ev.sec = (uint32_t)ts.tv_sec;
        ev.usec = (uint32_t)(ts.tv_nsec / 1000);
        ev.type = EV_SYN;
        ev.code = SYN_REPORT;
        (void)!write(g_uinput, &ev, sizeof(ev));
    }
}

static long read_weight(void) {
    char buf[32] = {0};
    if (read_file(WEIGHT_FILE, buf, sizeof(buf)) <= 0) return 0;
    return strtol(buf, NULL, 10);
}

static void set_weight(long grams) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%ld\n", grams);
    write_file(WEIGHT_FILE, buf);
}

static void snapshot_json(char *out, size_t cap) {
    char keys[9];
    keys_read(keys);
    size_t used = 0;
    used += (size_t)snprintf(out + used, cap - used,
        "{\"ok\":true,\"keys\":\"%s\",\"weight_g\":%ld,\"uinput\":%s,\"event0\":\"%s\"",
        keys, read_weight(), g_uinput >= 0 ? "true" : "false",
        g_event_is_fifo ? "fifo" : "evdev");
    const char *leds[] = {"AGSA_DRV_PHASE","AGSA_DRV_MODE1","AGSA_DRV_MODE2",
                          "AGSA_DRV_nSLEEP","AGSA_EN","FAN1_EN","FAN2_EN","USB_EN",NULL};
    used += (size_t)snprintf(out + used, cap - used, ",\"leds\":{");
    for (int i = 0; leds[i]; i++) {
        char p[256], v[32] = "?";
        snprintf(p, sizeof(p), "/sys/class/leds/%s/brightness", leds[i]);
        read_file(p, v, sizeof(v));
        char *nl = strchr(v, '\n'); if (nl) *nl = 0;
        used += (size_t)snprintf(out + used, cap - used, "%s\"%s\":\"%s\"",
                                 i ? "," : "", leds[i], v);
    }
    char bl[32] = "?";
    read_file("/sys/class/backlight/backlight/brightness", bl, sizeof(bl));
    char *nl = strchr(bl, '\n'); if (nl) *nl = 0;
    char gp[16] = "0";
    read_file("/sys/class/gpio/gpio59/value", gp, sizeof(gp));
    nl = strchr(gp, '\n'); if (nl) *nl = 0;
    char wd[32] = "";
    struct stat st;
    if (stat("/dev/watchdog", &st) == 0) snprintf(wd, sizeof(wd), "%lld", (long long)st.st_size);
    used += (size_t)snprintf(out + used, cap - used,
        "},\"backlight\":\"%s\",\"gpio59\":\"%s\",\"watchdog_bytes\":%s,"
        "\"timer_pulse_length\":\"", bl, gp, wd[0] ? wd : "0");
    char pl[32] = "?";
    read_file("/sys/bus/platform/drivers/stm32-one-pulse/40000000.timer:op/pulse_length", pl, sizeof(pl));
    nl = strchr(pl, '\n'); if (nl) *nl = 0;
    used += (size_t)snprintf(out + used, cap - used, "%s\"", pl);
    used += (size_t)snprintf(out + used, cap - used,
        ",\"hw\":{\"agsa_ma\":%ld,\"ntc1_mv\":%ld,\"ntc2_mv\":%ld,"
        "\"ddd_mv\":%ld,\"fan_rpm\":%ld},\"ttySTM0\":%s}",
        g_agsa_ma, g_ntc1_mv, g_ntc2_mv, g_ddd_mv, g_fan_rpm,
        g_tty0_master >= 0 ? "true" : "false");
}

static void write_state_file(void) {
    char json[4096];
    snapshot_json(json, sizeof(json));
    write_file(STATE_FILE, json);
}

/* ------------------------------------------------------------- commands */

static void reply(const char *fmt, ...) {
    char body[8192];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(body, sizeof(body) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(body) - 2) n = sizeof(body) - 2;
    char buf[8300];
    int out = 0;
    if (g_seq > 0 && body[0] == '{') {
        out = snprintf(buf, sizeof(buf), "{\"seq\":%d,", g_seq);
        if (out < 0 || out >= (int)sizeof(buf)) { out = 0; }
        int copy = n - 1; /* skip the opening brace */
        if (out + copy > (int)sizeof(buf) - 2) copy = (int)sizeof(buf) - 2 - out;
        memcpy(buf + out, body + 1, (size_t)copy);
        out += copy;
    } else {
        memcpy(buf, body, (size_t)n);
        out = n;
    }
    buf[out++] = '\n';
    if (g_ctrl >= 0) {
        ssize_t off = 0;
        while (off < out) {
            ssize_t w = write(g_ctrl, buf + off, (size_t)(out - off));
            if (w <= 0) { vglog("reply write failed: %s", strerror(errno)); break; }
            off += w;
        }
    }
}

static void reply_error(const char *msg) {
    char esc[512];
    json_escape(msg, esc, sizeof(esc));
    reply("{\"ok\":false,\"error\":\"%s\"}", esc);
}

static void cmd_exec(const char *cmd) {
    vglog("exec start: %s", cmd);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        vglog("exec popen failed: %s", strerror(errno));
        reply_error("popen failed");
        return;
    }
    char out[6000];
    size_t used = 0;
    size_t n;
    while ((n = fread(out + used, 1, sizeof(out) - used - 1, fp)) > 0) {
        used += n;
        if (used >= sizeof(out) - 1) break;
    }
    out[used] = 0;
    int rc = pclose(fp);
    vglog("exec done rc=%d len=%zu", rc, used);
    char esc[7000];
    json_escape(out, esc, sizeof(esc));
    reply("{\"ok\":true,\"exit\":%d,\"stdout\":\"%s\"}", WIFEXITED(rc) ? WEXITSTATUS(rc) : -1, esc);
    vglog("exec reply sent");
}

static int starts_with(const char *s, const char *p) {
    return strncmp(s, p, strlen(p)) == 0;
}

static void handle_line(char *line) {
    while (*line == ' ' || *line == '\t') line++;
    if (line[0] == '#') {
        char *space = strchr(line, ' ');
        if (space) {
            g_seq = atoi(line + 1);
            line = space + 1;
        }
    }
    size_t len = strlen(line);
    while (len && (line[len-1] == '\r' || line[len-1] == '\n' || line[len-1] == ' ')) line[--len] = 0;
    if (!len) return;
    vglog("cmd: %s", line);

    if (!strcmp(line, "ping")) { reply("{\"ok\":true,\"pong\":true}"); return; }
    if (!strcmp(line, "state") || !strcmp(line, "snapshot")) {
        char json[4096];
        snapshot_json(json, sizeof(json));
        reply("%s", json);
        return;
    }
    if (starts_with(line, "key ")) {
        int idx = -1, val = 0;
        if (sscanf(line + 4, "%d %d", &idx, &val) == 2) {
            set_key(idx, val);
            write_state_file();
            reply("{\"ok\":true,\"key\":%d,\"value\":%d}", idx, val ? 1 : 0);
        } else reply_error("usage: key <idx> <0|1>");
        return;
    }
    if (starts_with(line, "press ")) {
        int idx = -1, ms = 150;
        if (sscanf(line + 6, "%d %d", &idx, &ms) >= 1) {
            if (ms < 10) ms = 10;
            if (ms > 10000) ms = 10000;
            set_key(idx, 1);
            write_state_file();
            usleep((useconds_t)ms * 1000);
            set_key(idx, 0);
            write_state_file();
            reply("{\"ok\":true,\"key\":%d,\"held_ms\":%d}", idx, ms);
        } else reply_error("usage: press <idx> [ms]");
        return;
    }
    if (starts_with(line, "rotate ")) {
        int clicks = atoi(line + 7);
        if (clicks == 0) { reply_error("clicks must be non-zero"); return; }
        if (emit_rotary(clicks) == 0) reply("{\"ok\":true,\"clicks\":%d}", clicks);
        else reply_error("rotary write failed");
        return;
    }
    if (starts_with(line, "hw ")) {
        char *save = NULL;
        char *key = strtok_r(line + 3, " ", &save);
        while (key) {
            char *val = strtok_r(NULL, " ", &save);
            if (!val) break;
            long v = strtol(val, NULL, 10);
            if (!strcmp(key, "agsa_ma")) g_agsa_ma = v;
            else if (!strcmp(key, "ntc1_mv")) g_ntc1_mv = v;
            else if (!strcmp(key, "ntc2_mv")) g_ntc2_mv = v;
            else if (!strcmp(key, "ddd_mv")) g_ddd_mv = v;
            else if (!strcmp(key, "fan_rpm")) g_fan_rpm = v;
            key = strtok_r(NULL, " ", &save);
        }
        write_hw_file();
        reply("{\"ok\":true,\"hw\":{\"agsa_ma\":%ld,\"ntc1_mv\":%ld,"
              "\"ntc2_mv\":%ld,\"ddd_mv\":%ld,\"fan_rpm\":%ld}}",
              g_agsa_ma, g_ntc1_mv, g_ntc2_mv, g_ddd_mv, g_fan_rpm);
        return;
    }
    if (starts_with(line, "weight ")) {
        long g = strtol(line + 7, NULL, 10);
        set_weight(g);
        write_state_file();
        reply("{\"ok\":true,\"weight_g\":%ld}", g);
        return;
    }
    if (starts_with(line, "led ")) {
        char name[64]; int val = -1;
        if (sscanf(line + 4, "%63s %d", name, &val) == 2) {
            char p[256];
            snprintf(p, sizeof(p), "/sys/class/leds/%s/brightness", name);
            char v[16]; snprintf(v, sizeof(v), "%d\n", val ? 1 : 0);
            if (write_file(p, v) == 0) { write_state_file(); reply("{\"ok\":true,\"led\":\"%s\",\"value\":%d}", name, val ? 1 : 0); }
            else reply_error("led not found");
        } else reply_error("usage: led <name> <0|1>");
        return;
    }
    if (starts_with(line, "backlight ")) {
        int val = atoi(line + 10);
        char v[16]; snprintf(v, sizeof(v), "%d\n", val);
        if (write_file("/sys/class/backlight/backlight/brightness", v) == 0) {
            write_state_file();
            reply("{\"ok\":true,\"backlight\":%d}", val);
        } else reply_error("backlight write failed");
        return;
    }
    if (starts_with(line, "hw ")) {
        char key[32]; long val = 0;
        if (sscanf(line + 3, "%31s %ld", key, &val) == 2) {
            if (set_hw(key, val) == 0)
                reply("{\"ok\":true,\"hw\":\"%s\",\"value\":%ld}", key, val);
            else reply_error("unknown hw key");
        } else reply_error("usage: hw <key> <value>");
        return;
    }
    if (starts_with(line, "exec ")) { cmd_exec(line + 5); return; }
    if (!strcmp(line, "reboot")) { reply("{\"ok\":true,\"action\":\"reboot\"}"); sync(); reboot(RB_AUTOBOOT); return; }
    if (!strcmp(line, "poweroff")) { reply("{\"ok\":true,\"action\":\"poweroff\"}"); sync(); reboot(RB_POWER_OFF); return; }
    reply_error("unknown command");
}

/* ------------------------------------------------------------- devmem */

/* busybox devmem cannot mmap /dev/mem under QEMU, so the vendor timer/ADC
 * scripts do `val=$(devmem $reg)` on an empty string and die with
 * "arithmetic syntax error". Replace the applet with a persistent 32-bit
 * register window under /tmp/vg/devmem. The original busybox applet is still
 * reachable as `/bin/busybox devmem`. Emulation-only. */
static void install_devmem_model(void)
{
    struct stat st;
    if (lstat("/sbin/devmem", &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            unlink("/sbin/devmem");
        } else if (S_ISREG(st.st_mode)) {
            rename("/sbin/devmem", "/sbin/devmem.vg-orig");
        }
    }
    const char *script =
        "#!/bin/sh\n"
        "# vg: emulated STM32 register window (state under /tmp/vg/devmem)\n"
        "addr=$(( $1 ))\n"
        "mkdir -p /tmp/vg/devmem\n"
        "f=/tmp/vg/devmem/$(printf '%08x' $addr)\n"
        "if [ $# -le 1 ]; then\n"
        "  if [ -f $f ]; then cat $f; else echo 0; fi\n"
        "else\n"
        "  printf '%u\\n' $(( $3 )) > $f\n"
        "fi\n";
    int fd = open("/sbin/devmem", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        vglog("devmem model install failed: %s", strerror(errno));
        return;
    }
    size_t n = strlen(script);
    (void)!write(fd, script, n);
    close(fd);
    chmod("/sbin/devmem", 0755);
    vglog("devmem model installed");
}

/* IIO buffer/enable transitions are logged so the sequencing of the vendor
 * scripts and the HMI's own AdcDmaReader::disable() is observable. */
static void *iio_buffer_thread(void *arg)
{
    (void)arg;
    int last[4] = {-1, -1, -1, -1};
    char p[256], b[32];
    for (;;) {
        for (int d = 3; d <= 6; d++) {
            snprintf(p, sizeof(p), "/sys/bus/iio/devices/iio:device%d/buffer/enable", d);
            b[0] = 0;
            if (read_file(p, b, sizeof(b)) > 0) {
                int on = atoi(b) != 0;
                if (last[d - 3] != on) {
                    last[d - 3] = on;
                    vglog("iio:device%d buffer/enable=%d", d, on);
                }
            }
        }
        struct timespec ts = {0, 250 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* --------------------------------------------------------------- startup */

static int open_control(void) {
    /* Port order is fixed by the QEMU command line: p1=ESP, p2=JSON, p3=agent.
       Fall back to scanning and greeting so a reordered command line still
       works (the host daemon sends "ping" on its side). */
    const char *preferred[] = {"/dev/vport0p3", "/dev/vport0p4", "/dev/vport0p5", NULL};
    for (int i = 0; preferred[i]; i++) {
        if (access(preferred[i], F_OK) != 0) continue;
        int fd = open(preferred[i], O_RDWR | O_NOCTTY);
        if (fd >= 0) { vglog("control port %s", preferred[i]); return fd; }
    }
    for (int p = 1; p <= CTRL_CANDIDATES; p++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/vport0p%d", p);
        if (access(path, F_OK) != 0) continue;
        int fd = open(path, O_RDWR | O_NOCTTY);
        if (fd >= 0) { vglog("control port fallback %s", path); return fd; }
    }
    return -1;
}

int main(void) {
    mkdir_p(VG_DIR, 0777);
    mkdir_p("/dev/input", 0755);
    if (access(KEYS_FILE, F_OK) != 0) write_file(KEYS_FILE, "00000000");
    if (access(WEIGHT_FILE, F_OK) != 0) write_file(WEIGHT_FILE, "0\n");
    if (access(HW_FILE, F_OK) != 0) write_hw_file();
    load_hw();
    install_devmem_model();
    load_loadcell_calibration();
    vglog("starting");

    /* This kernel has no IIO bus at all. Mount a small tmpfs over /sys/bus so
     * the vendor's hardcoded /sys/bus/iio/devices tree can exist, and recreate
     * the platform/nvmem mountpoints the overlays below expect. */
    if (access("/sys/bus/iio", F_OK) != 0) {
        if (mount("tmpfs", "/sys/bus", "tmpfs", 0, "mode=755,size=4096k") == 0) {
            mkdir_p("/sys/bus/iio/devices", 0755);
            mkdir_p("/sys/bus/platform/drivers", 0755);
            mkdir_p("/sys/bus/platform/devices", 0755);
            mkdir_p("/sys/bus/nvmem/devices", 0755);
            vglog("sys/bus tmpfs installed (no IIO bus in kernel)");
        } else {
            vglog("sys/bus tmpfs mount failed: %s", strerror(errno));
        }
    }

    for (size_t i = 0; i < sizeof(g_overlays) / sizeof(g_overlays[0]); i++)
        mount_overlay(g_overlays[i].path);
    seed_sysfs();
    {
        pthread_t thread;
        if (pthread_create(&thread, NULL, iio_buffer_thread, NULL) == 0)
            pthread_detach(thread);
        if (pthread_create(&thread, NULL, hw_refresh_thread, NULL) == 0)
            pthread_detach(thread);
    }

    g_uinput = setup_uinput();
    if (g_uinput < 0) setup_rotary_fifo();
    write_state_file();

    g_ctrl = open_control();
    if (g_ctrl < 0) {
        vglog("no control port found; state-only mode");
        for (;;) { write_state_file(); sleep(5); }
    }
    setup_tty_relay();
    setup_console_tty();
    write_state_file();

    char line[8192];
    size_t used = 0;
    for (;;) {
        char buf[512];
        ssize_t n = read(g_ctrl, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) { usleep(20000); continue; }
            vglog("control read: %s", strerror(errno));
            sleep(1);
            continue;
        }
        if (n == 0) { usleep(50000); continue; }
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\n' || used >= sizeof(line) - 1) {
                line[used] = 0;
                handle_line(line);
                used = 0;
            } else if (buf[i] != '\r') {
                line[used++] = buf[i];
            }
        }
    }
    return 0;
}
