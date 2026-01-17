#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "cmdline.h"

pid_t child_proc = -1;
struct gengetopt_args_info args_info;
#define CAP_SYS_ADMIN_IDX 21
#define CAP_SYS_ADMIN_BIT (1ULL << CAP_SYS_ADMIN_IDX)
extern char **environ;

static void normalize_debug_argv(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], "-debug") == 0) {
            argv[i] = (char *)"--debug";
        }
    }
}

static void strip_cookie_inplace(char *s) {
    if (s == NULL) {
        return;
    }
    size_t w = 0;
    for (size_t r = 0; s[r] != '\0'; r++) {
        if (s[r] == '\n' || s[r] == '\r') {
            continue;
        }
        s[w++] = s[r];
    }
    s[w] = '\0';
    while (w > 0) {
        char c = s[w - 1];
        if (c == ' ' || c == '\t') {
            s[w - 1] = '\0';
            w--;
            continue;
        }
        break;
    }
}

static char *read_cookie_from_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long size = ftell(fp);
    if (size <= 0 || size > 256 * 1024) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)size + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    if (n == 0) {
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    strip_cookie_inplace(buf);
    if (buf[0] == '\0') {
        free(buf);
        return NULL;
    }
    return buf;
}

static int try_load_cookie_txt(char **out_cookie_path) {
    if (out_cookie_path) {
        *out_cookie_path = NULL;
    }
    const char *already = getenv("WRAPPER_COOKIE");
    if (already && already[0]) {
        return 1;
    }

    char exe_path[PATH_MAX + 1];
    ssize_t exe_len = readlink("/proc/self/exe", exe_path, PATH_MAX);
    if (exe_len <= 0) {
        return 0;
    }
    exe_path[exe_len] = '\0';
    char *last_slash = strrchr(exe_path, '/');
    if (!last_slash) {
        return 0;
    }
    *last_slash = '\0';
    size_t dir_len = strlen(exe_path);
    const char *cookie_name = "/cookie.txt";
    size_t cookie_len = dir_len + strlen(cookie_name);
    char *cookie_path = (char *)malloc(cookie_len + 1);
    if (!cookie_path) {
        return 0;
    }
    memcpy(cookie_path, exe_path, dir_len);
    memcpy(cookie_path + dir_len, cookie_name, strlen(cookie_name) + 1);

    char *cookie = read_cookie_from_file(cookie_path);
    if (!cookie) {
        free(cookie_path);
        return 0;
    }
    setenv("WRAPPER_COOKIE", cookie, 1);
    free(cookie);
    if (out_cookie_path) {
        *out_cookie_path = cookie_path;
    } else {
        free(cookie_path);
    }
    return 1;
}

static void intHan(int signum) {
    if (child_proc != -1) {
        kill(child_proc, SIGKILL);
    }
}

int has_cap_sys_admin() {
    FILE *fp;
    char line[256];
    unsigned long long cap_eff = 0;
    int found_cap_eff = 0;

    fp = fopen("/proc/self/status", "r");
    if (fp == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            char *value_str = line + 7;
            while (*value_str == '\t' || *value_str == ' ') {
                value_str++;
            }
            cap_eff = strtoull(value_str, NULL, 16);
            found_cap_eff = 1;
            break;
        }
    }

    fclose(fp);

    if (!found_cap_eff) {
        return 0;
    }

    if (cap_eff & CAP_SYS_ADMIN_BIT) {
        return 1;
    } else {
        return 0;
    }
}

int main(int argc, char *argv[], char *envp[]) {
    normalize_debug_argv(argc, argv);
    cmdline_parser(argc, argv, &args_info);
    if (signal(SIGINT, intHan) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    char *cookie_path = NULL;
    int cookie_loaded = try_load_cookie_txt(&cookie_path);
    if (args_info.debug_flag) {
        fprintf(stderr, "[debug] wrapper start\n");
        if (cookie_loaded) {
            fprintf(stderr, "[debug] cookie loaded: %s\n", cookie_path ? cookie_path : "(env)");
        } else {
            fprintf(stderr, "[debug] cookie not found\n");
        }
    }
    if (cookie_path) {
        free(cookie_path);
    }

    if (chdir("./rootfs") != 0) {
        perror("chdir");
        return 1;
    }
    if (chroot("./") != 0) {
        perror("chroot");
        return 1;
    }
    setenv("ANDROID_DATA", "/data", 1);
    setenv("ANDROID_ROOT", "/system", 1);

    mkdir("/data", 0777);
    mkdir("/data/misc", 0777);
    mkdir("/data/misc/zoneinfo", 0777);
    mkdir("/data/misc/zoneinfo/current", 0777);
    mknod("/dev/urandom", S_IFCHR | 0666, makedev(0x1, 0x9));
    chmod("/system/bin/linker64", 0755);
    chmod("/system/bin/main", 0755);

    if (has_cap_sys_admin()) {
        if (unshare(CLONE_NEWPID)) {
            perror("unshare");
            return 1;
        }
    }

    child_proc = fork();
    if (child_proc == -1) {
        perror("fork");
        return 1;
    }

    if (child_proc > 0) {
        wait(NULL);
        return 0;
    }

    // Child process logic
    mkdir(args_info.base_dir_arg, 0777);
    size_t mpl_db_len = strlen(args_info.base_dir_arg) + strlen("/mpl_db");
    char *mpl_db_dir = (char *)malloc(mpl_db_len + 1);
    if (mpl_db_dir) {
        strcpy(mpl_db_dir, args_info.base_dir_arg);
        strcat(mpl_db_dir, "/mpl_db");
        mkdir(mpl_db_dir, 0777);
        free(mpl_db_dir);
    }
    if (args_info.debug_flag) {
        fprintf(stderr, "[debug] exec /system/bin/main\n");
    }
    execve("/system/bin/main", argv, environ);
    perror("execve");
    return 1;
}
