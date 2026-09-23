#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>

static int read_file(const char* path, char* buf, size_t n) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, n - 1);
    close(fd);
    if (r <= 0) return -1;
    buf[r] = 0;
    return (int)r;
}

static int tracer_pid() {
    char buf[512];
    if (read_file("/proc/self/status", buf, sizeof(buf)) < 0) return 0;
    const char* p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    return atoi(p + 10);
}

static int maps_hit() {
    char buf[16384];
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;
    int hit = 0;
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[r] = 0;
        if (strcasestr(buf, "frida") || strcasestr(buf, "gadget") ||
            strcasestr(buf, "xposed") || strcasestr(buf, "lsposed") ||
            strcasestr(buf, "substrate") || strcasestr(buf, "libhook") ||
            strcasestr(buf, "frida-agent") || strcasestr(buf, "linjector")) {
            hit = 1;
            break;
        }
    }
    close(fd);
    return hit;
}

static int port_open(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    struct sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct timeval tv{0, 60000};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int ok = (connect(s, (struct sockaddr*)&a, sizeof(a)) == 0);
    close(s);
    return ok ? 1 : 0;
}

static int path_exists(const char* p) {
    return access(p, F_OK) == 0;
}

static int root_hint() {
    const char* paths[] = {
        "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/sbin/.magisk",
        "/data/adb/magisk", "/data/adb/modules", nullptr
    };
    for (int i = 0; paths[i]; i++) if (path_exists(paths[i])) return 1;
    return 0;
}

static int fd_frida() {
    char path[64], link[256];
    for (int fd = 0; fd < 256; fd++) {
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(path, link, sizeof(link) - 1);
        if (n > 0) {
            link[n] = 0;
            if (strcasestr(link, "frida") || strcasestr(link, "linjector")) return 1;
        }
    }
    return 0;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_alvsia_pro_sec_NativeGuard_nativeScan(JNIEnv*, jclass) {
    int flags = 0;
    if (tracer_pid() > 0) flags |= 1;
    if (maps_hit()) flags |= 2;
    if (port_open(27042) || port_open(27043) || port_open(23946) || port_open(8888)) flags |= 4;
    if (root_hint()) flags |= 8;
    if (path_exists("/data/local/tmp/frida-server") ||
        path_exists("/data/local/tmp/re.frida.server") ||
        path_exists("/data/local/tmp/hluda-server")) flags |= 16;
    if (fd_frida()) flags |= 32;
    return flags;
}

extern "C" JNIEXPORT void JNICALL
Java_com_alvsia_pro_sec_NativeGuard_nativeWipe(JNIEnv* env, jclass, jbyteArray arr) {
    if (!arr) return;
    jsize n = env->GetArrayLength(arr);
    jbyte* p = env->GetByteArrayElements(arr, nullptr);
    if (p) {
        memset(p, 0, (size_t)n);
        env->ReleaseByteArrayElements(arr, p, 0);
    }
}
