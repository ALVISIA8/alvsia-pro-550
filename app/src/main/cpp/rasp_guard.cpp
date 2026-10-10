// ALVISIA PRO 5.5.0 — librasp_guard.so
// Anti-debug / anti-dump / anti-hook native layer
// Build: CMakeLists.txt target librasp_guard
// ABI: arm64-v8a (primary), armeabi-v7a (secondary)
// Compiler: clang++ (NDK r25c+)  C++17  -O2  -fvisibility=hidden  -fstack-protector-all
//           -Wl,--strip-all  -ffunction-sections  -fdata-sections  -Wl,--gc-sections

#include <jni.h>
#include <android/log.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <dlfcn.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "RASP_N", __VA_ARGS__)

// ── Bit masks returned by nativeScanFlags() ──────────────────────────
static constexpr int FLAG_TRACER_PID      = 0x01;
static constexpr int FLAG_MAPS_FRIDA      = 0x02;
static constexpr int FLAG_PTRACE_ERROR    = 0x04;
static constexpr int FLAG_HW_BREAKPOINT   = 0x08;
static constexpr int FLAG_INLINE_HOOK     = 0x10;
static constexpr int FLAG_CAP_OVERGRANTED = 0x20;
static constexpr int FLAG_SELF_HASH_BAD   = 0x40;
static constexpr int FLAG_TIMING_PTRACE   = 0x80;

// ─────────────────────────────────────────────────────────────────────
// 1. TracerPid check
// ─────────────────────────────────────────────────────────────────────
static int check_tracer_pid() {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    char buf[2048] = {};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    const char* p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    int tpid = atoi(p + 10);
    return (tpid > 0) ? FLAG_TRACER_PID : 0;
}

// ─────────────────────────────────────────────────────────────────────
// 2. /proc/self/maps — Frida / hook library markers
// ─────────────────────────────────────────────────────────────────────
static const char* MAP_NEEDLES[] = {
    "frida-agent", "frida-gadget", "frida_agent", "libfrida",
    "libgadget", "xposed", "lsposed", "edxposed",
    "substrate", "libsubstrate", "libsandhook", "libepic",
    "riru", "zygisk", "linjector", "libdobby", "dobby",
    "shadowhook", "bhook", "bytehook",
    nullptr
};

static int check_maps_frida() {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;
    char buf[131072] = {};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    // lowercase in-place
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] >= 'A' && buf[i] <= 'Z') buf[i] += 32;
    }
    for (int i = 0; MAP_NEEDLES[i]; i++) {
        if (strstr(buf, MAP_NEEDLES[i])) return FLAG_MAPS_FRIDA;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────
// 3. Non-invasive ptrace state check
// Never call PTRACE_TRACEME from the app itself: it changes the process
// tracing state and PTRACE_DETACH from the tracee is not a valid rollback.
// /proc/self/status is already checked by check_tracer_pid() above.
// ─────────────────────────────────────────────────────────────────────
static int check_ptrace_traceme() {
    return check_tracer_pid() ? FLAG_PTRACE_ERROR : 0;
}

// ─────────────────────────────────────────────────────────────────────
// 4. Hardware breakpoint detection via ptrace GETREGSET (arm64)
// ─────────────────────────────────────────────────────────────────────
static int check_hw_breakpoint() {
    // Read NT_ARM_HW_BREAK from own process via a short-lived child
    // that ptraces the parent and checks DBGBCR registers.
    // Simplified: check /proc/self/status for "StopSignal" or use timing.
    // Full impl requires fork + ptrace child (complex inline here).
    // We use timing side-channel instead (see check_timing_ptrace).
    return 0;
}

// ─────────────────────────────────────────────────────────────────────
// 5. Inline hook detection in libc / libdvm / libart .text section
//    Checks first 4 bytes of known functions for B/BL jump patch.
// ─────────────────────────────────────────────────────────────────────
static int check_inline_hook() {
    // Load libc and check strlen prologue — hooked by many frameworks
    void* libc = dlopen("libc.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!libc) return 0;
    void* fn = dlsym(libc, "strcmp");
    if (!fn) { dlclose(libc); return 0; }
    // On clean arm64: first instruction is NOT a branch to hook trampoline
    // B instruction encoding: top 6 bits = 0x14 or 0x17 for unconditional branch
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(fn);
    // Check for unconditional branch (B = 0x14xxxxxx or BL = 0x94xxxxxx in arm64 LE)
    uint32_t instr = 0;
    memcpy(&instr, bytes, 4);
    uint32_t op = instr >> 26;
    int hooked = (op == 0x05 || op == 0x25) ? FLAG_INLINE_HOOK : 0; // B=0x05, BL=0x25
    dlclose(libc);
    return hooked;
}

// ─────────────────────────────────────────────────────────────────────
// 6. Capability overgranting (CapEff full set = process runs as root)
// ─────────────────────────────────────────────────────────────────────
static int check_cap_overgranted() {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096] = {};
    read(fd, buf, sizeof(buf) - 1);
    close(fd);
    const char* p = strstr(buf, "CapEff:");
    if (!p) return 0;
    unsigned long long capeff = strtoull(p + 7, nullptr, 16);
    // 0x3fffffffff = all caps set (root-equivalent in most kernels)
    return (capeff == 0x3fffffffffffffffULL || capeff == 0x3fffffffffULL)
        ? FLAG_CAP_OVERGRANTED : 0;
}

// ─────────────────────────────────────────────────────────────────────
// 7. Self-page hash — detect if our own .text was patched after load
//    Simplified: hash first 4 KB of this .so's .text via dladdr
// ─────────────────────────────────────────────────────────────────────
static volatile uint32_t g_text_hash_baseline = 0;

static uint32_t hash_region(const uint8_t* p, size_t len) {
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x01000193u;
    }
    return h;
}

static void init_self_hash() {
    Dl_info info;
    if (!dladdr(reinterpret_cast<void*>(init_self_hash), &info)) return;
    if (!info.dli_fbase) return;
    const uint8_t* base = reinterpret_cast<const uint8_t*>(info.dli_fbase);
    g_text_hash_baseline = hash_region(base, 4096);
}

static int check_self_hash() {
    if (g_text_hash_baseline == 0) return 0; // not initialized
    Dl_info info;
    if (!dladdr(reinterpret_cast<void*>(check_self_hash), &info)) return 0;
    if (!info.dli_fbase) return 0;
    const uint8_t* base = reinterpret_cast<const uint8_t*>(info.dli_fbase);
    uint32_t current = hash_region(base, 4096);
    return (current != g_text_hash_baseline) ? FLAG_SELF_HASH_BAD : 0;
}

// ─────────────────────────────────────────────────────────────────────
// 8. Timing-based ptrace detection (debugger slows clock_gettime)
// ─────────────────────────────────────────────────────────────────────
static int check_timing_ptrace() {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    // A few volatile reads to create a measurable interval
    volatile int sink = 0;
    for (int i = 0; i < 1000; i++) sink += i;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int64_t ns = ((int64_t)(t1.tv_sec - t0.tv_sec)) * 1000000000LL
                + (t1.tv_nsec - t0.tv_nsec);
    // Under a debugger single-step, this loop takes >> 5 ms
    return (ns > 5000000LL) ? FLAG_TIMING_PTRACE : 0;
}

// ─────────────────────────────────────────────────────────────────────
// JNI exports
// ─────────────────────────────────────────────────────────────────────
extern "C" {

JNIEXPORT jint JNICALL
Java_com_alvsia_pro_sec_NativeGuard_nativeScanFlags(JNIEnv*, jobject) {
    int flags = 0;
    flags |= check_tracer_pid();
    flags |= check_maps_frida();
    flags |= check_ptrace_traceme();
    flags |= check_hw_breakpoint();
    flags |= check_inline_hook();
    flags |= check_cap_overgranted();
    flags |= check_self_hash();
    flags |= check_timing_ptrace();
    return (jint)flags;
}

JNIEXPORT void JNICALL
Java_com_alvsia_pro_sec_NativeGuard_nativeWipe(JNIEnv* env, jobject, jbyteArray arr) {
    if (!arr) return;
    jsize len = env->GetArrayLength(arr);
    if (len <= 0) return;
    jbyte* p = env->GetByteArrayElements(arr, nullptr);
    if (!p) return;
    memset(p, 0, (size_t)len);
    env->ReleaseByteArrayElements(arr, p, 0);
}

JNIEXPORT jint JNICALL
Java_com_alvsia_pro_sec_NativeGuard_nativeAntiDump(JNIEnv*, jobject) {
    // Scan all pids: detect open fd to /proc/<self>/mem
    int selfpid = (int)getpid();
    char selfmem[64];
    snprintf(selfmem, sizeof(selfmem), "/proc/%d/mem", selfpid);
    int found = 0;

    DIR* proc = opendir("/proc");
    if (!proc) return 0;
    struct dirent* de;
    while ((de = readdir(proc)) != nullptr) {
        int pid = atoi(de->d_name);
        if (pid == 0 || pid == selfpid) continue;
        char fddir[64];
        snprintf(fddir, sizeof(fddir), "/proc/%d/fd", pid);
        DIR* fdd = opendir(fddir);
        if (!fdd) continue;
        struct dirent* fde;
        while ((fde = readdir(fdd)) != nullptr) {
            char fdpath[128];
            snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/%s", pid, fde->d_name);
            char link[256] = {};
            if (readlink(fdpath, link, sizeof(link) - 1) > 0) {
                if (strcmp(link, selfmem) == 0) { found++; }
            }
        }
        closedir(fdd);
    }
    closedir(proc);
    return (jint)found;
}

JNIEXPORT jbyteArray JNICALL
Java_com_alvsia_pro_sec_NativeGuard_nativeSealSeed(JNIEnv* env, jobject) {
    // Unique per-build obfuscation input; this is not a server-side secret.
    static const char seedHex[] = ALVSIA_SEAL_SEED_HEX;
    unsigned char seed[32] = {};
    for (size_t i = 0; i < 32; ++i) {
        unsigned int value = 0;
        if (sscanf(seedHex + (i * 2), "%2x", &value) != 1) return nullptr;
        seed[i] = static_cast<unsigned char>(value);
    }
    jbyteArray out = env->NewByteArray(32);
    if (out == nullptr) return nullptr;
    env->SetByteArrayRegion(out, 0, 32, reinterpret_cast<const jbyte*>(seed));
    memset(seed, 0, sizeof(seed));
    return out;
}

// Library load init — called by dynamic linker
__attribute__((constructor))
static void on_load() {
    init_self_hash();
}

} // extern "C"
