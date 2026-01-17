#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

#include "cmdline.h"

extern char **environ;

pid_t child_proc = -1;
struct gengetopt_args_info args_info;
#if defined(WRAPPER_EMBED_ROOTFS)
extern const unsigned char _binary_rootfs_tar_start[];
extern const unsigned char _binary_rootfs_tar_end[];
#endif

static int g_debug = 0;

static void debugf(const char *fmt, ...) {
    if (!g_debug) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[debug] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    fflush(stderr);
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int ensure_dir(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0) {
        return 1;
    }
    if (errno == EEXIST) {
        return 1;
    }
    return 0;
}

static int ensure_parent_dirs(const char *path) {
    char buf[PATH_MAX];
    size_t len = strnlen(path, sizeof(buf));
    if (len == 0 || len >= sizeof(buf)) {
        return 0;
    }
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (!ensure_dir(buf, 0755)) {
                return 0;
            }
            *p = '/';
        }
    }
    return 1;
}

static int copy_file_if_missing(const char *src, const char *dst, mode_t mode) {
    if (file_exists(dst)) {
        return 1;
    }
    if (!ensure_parent_dirs(dst)) {
        return 0;
    }

    int in_fd = open(src, O_RDONLY);
    if (in_fd < 0) {
        return 0;
    }

    int out_fd = open(dst, O_CREAT | O_TRUNC | O_WRONLY, mode);
    if (out_fd < 0) {
        close(in_fd);
        return 0;
    }

    char buf[8192];
    while (1) {
        ssize_t rd = read(in_fd, buf, sizeof(buf));
        if (rd == 0) {
            break;
        }
        if (rd < 0) {
            close(in_fd);
            close(out_fd);
            return 0;
        }
        ssize_t off = 0;
        while (off < rd) {
            ssize_t wr = write(out_fd, buf + off, (size_t)(rd - off));
            if (wr <= 0) {
                close(in_fd);
                close(out_fd);
                return 0;
            }
            off += wr;
        }
    }

    close(in_fd);
    close(out_fd);
    return 1;
}

static void try_install_tzdata_into_rootfs(const char *rootfs_dir) {
    const char *candidates[] = {
        "/usr/share/zoneinfo/tzdata",
        "/usr/share/zoneinfo-icu/tzdata.dat",
        NULL,
    };

    const char *src = NULL;
    for (int i = 0; candidates[i]; ++i) {
        if (file_exists(candidates[i])) {
            src = candidates[i];
            break;
        }
    }
    if (!src) {
        if (g_debug) {
            fprintf(stderr, "[debug] tzdata source not found on host\n");
            fflush(stderr);
        }
        return;
    }

    char dst1[PATH_MAX];
    char dst2[PATH_MAX];
    snprintf(dst1, sizeof(dst1), "%s/system/usr/share/zoneinfo/tzdata", rootfs_dir);
    snprintf(dst2, sizeof(dst2), "%s/data/misc/zoneinfo/tzdata", rootfs_dir);

    int ok1 = copy_file_if_missing(src, dst1, 0644);
    int ok2 = copy_file_if_missing(src, dst2, 0644);
    if (g_debug) {
        fprintf(stderr, "[debug] tzdata src=%s dst1=%s ok=%d exists=%d\n", src, dst1, ok1, file_exists(dst1));
        fprintf(stderr, "[debug] tzdata src=%s dst2=%s ok=%d exists=%d\n", src, dst2, ok2, file_exists(dst2));
        fflush(stderr);
    }
}

static unsigned long parse_octal(const char *s, size_t n) {
    unsigned long v = 0;
    for (size_t i = 0; i < n; ++i) {
        if (s[i] == '\0') break;
        if (s[i] < '0' || s[i] > '7') continue;
        v = (v << 3) + (unsigned long)(s[i] - '0');
    }
    return v;
}

static int should_skip_extract_path(const char *rel_path) {
    if (strncmp(rel_path, "./", 2) == 0) {
        rel_path += 2;
    }
    if (strncmp(rel_path, "data/", 5) == 0) {
        return 1;
    }
    return 0;
}

static int extract_tar_to_dir(const unsigned char *tar, size_t tar_size, const char *out_dir) {
    if (!ensure_parent_dirs(out_dir)) {
        return 0;
    }
    if (!ensure_dir(out_dir, 0755)) {
        return 0;
    }

    size_t off = 0;
    while (off + 512 <= tar_size) {
        const unsigned char *hdr = tar + off;
        int all_zero = 1;
        for (size_t i = 0; i < 512; ++i) {
            if (hdr[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            break;
        }

        char name[101];
        char prefix[156];
        memcpy(name, hdr + 0, 100);
        name[100] = '\0';
        memcpy(prefix, hdr + 345, 155);
        prefix[155] = '\0';

        char rel_path[PATH_MAX];
        if (prefix[0]) {
            snprintf(rel_path, sizeof(rel_path), "%s/%s", prefix, name);
        } else {
            snprintf(rel_path, sizeof(rel_path), "%s", name);
        }

        char out_path[PATH_MAX];
        if (snprintf(out_path, sizeof(out_path), "%s/%s", out_dir, rel_path) >= (int)sizeof(out_path)) {
            return 0;
        }

        unsigned long mode = parse_octal((const char *)(hdr + 100), 8);
        unsigned long size = parse_octal((const char *)(hdr + 124), 12);
        char typeflag = (char)hdr[156];

        off += 512;

        if (rel_path[0] == '\0') {
            continue;
        }

        if (typeflag == '5') {
            if (!ensure_parent_dirs(out_path)) {
                return 0;
            }
            if (!ensure_dir(out_path, (mode_t)(mode ? mode : 0755))) {
                return 0;
            }
            continue;
        }

        if (typeflag == '2') {
            char linkname[101];
            memcpy(linkname, hdr + 157, 100);
            linkname[100] = '\0';
            if (!ensure_parent_dirs(out_path)) {
                return 0;
            }
            if (should_skip_extract_path(rel_path) && file_exists(out_path)) {
                continue;
            }
            unlink(out_path);
            if (symlink(linkname, out_path) != 0) {
                return 0;
            }
            continue;
        }

        if (!ensure_parent_dirs(out_path)) {
            return 0;
        }
        if (should_skip_extract_path(rel_path) && file_exists(out_path)) {
            size_t blocks = (size + 511) / 512;
            off += blocks * 512;
            continue;
        }

        int fd = open(out_path, O_CREAT | O_TRUNC | O_WRONLY, (mode_t)(mode ? mode : 0644));
        if (fd == -1) {
            return 0;
        }

        size_t remaining = size;
        while (remaining > 0) {
            size_t chunk = remaining > 8192 ? 8192 : remaining;
            if (off + chunk > tar_size) {
                close(fd);
                return 0;
            }
            ssize_t wr = write(fd, tar + off, chunk);
            if (wr <= 0) {
                close(fd);
                return 0;
            }
            off += (size_t)wr;
            remaining -= (size_t)wr;
        }
        close(fd);

        size_t pad = (512 - (size % 512)) % 512;
        off += pad;
    }

    return 1;
}

static int strip_debug_arg(int argc, char **argv, char ***out_argv) {
    char **filtered = (char **)calloc((size_t)argc + 1, sizeof(char *));
    if (!filtered) {
        return -1;
    }

    int j = 0;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-debug") == 0) {
            g_debug = 1;
            continue;
        }
        filtered[j++] = argv[i];
    }
    filtered[j] = NULL;
    *out_argv = filtered;
    return j;
}

static const char *default_rootfs_dir(void) {
    const char *home = getenv("HOME");
    if (home && home[0]) {
        static char p[PATH_MAX];
        snprintf(p, sizeof(p), "%s/.wrapper/rootfs", home);
        return p;
    }
    return "/tmp/wrapper-rootfs";
}
#define CAP_SYS_ADMIN_IDX 21
#define CAP_SYS_ADMIN_BIT (1ULL << CAP_SYS_ADMIN_IDX)

static void intHan(int signum) {
    (void)signum;
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
    char **filtered_argv = NULL;
    int filtered_argc = strip_debug_arg(argc, argv, &filtered_argv);
    if (filtered_argc < 0) {
        fprintf(stderr, "[!] out of memory\n");
        return 1;
    }

    cmdline_parser(filtered_argc, filtered_argv, &args_info);
    if (args_info.debug_flag) {
        g_debug = 1;
    }
    if (g_debug) {
        setenv("WRAPPER_DEBUG", "1", 1);
    }
    if (signal(SIGINT, intHan) == SIG_ERR) {
        perror("signal");
        free(filtered_argv);
        return 1;
    }

    const char *rootfs_dir = NULL;
    if (file_exists("./rootfs")) {
        rootfs_dir = "./rootfs";
    } else {
#if defined(WRAPPER_EMBED_ROOTFS)
        rootfs_dir = default_rootfs_dir();
        if (!file_exists(rootfs_dir)) {
            debugf("extracting embedded rootfs to %s", rootfs_dir);
            if (!extract_tar_to_dir(_binary_rootfs_tar_start,
                                    (size_t)(_binary_rootfs_tar_end - _binary_rootfs_tar_start),
                                    rootfs_dir)) {
                fprintf(stderr, "[!] failed to extract embedded rootfs\n");
                free(filtered_argv);
                return 1;
            }
        }
#else
        fprintf(stderr, "[!] rootfs not found (expected ./rootfs)\n");
        free(filtered_argv);
        return 1;
#endif
    }

    setenv("WRAPPER_HOST_ROOTFS", rootfs_dir, 1);
    try_install_tzdata_into_rootfs(rootfs_dir);

    if (chdir(rootfs_dir) != 0) {
        perror("chdir");
        free(filtered_argv);
        return 1;
    }
    if (chroot("./") != 0) {
        perror("chroot");
        free(filtered_argv);
        return 1;
    }
    mknod("/dev/urandom", S_IFCHR | 0666, makedev(0x1, 0x9));
    chmod("/system/bin/linker64", 0755);
    chmod("/system/bin/main", 0755);

    if (has_cap_sys_admin()) {
        if (unshare(CLONE_NEWPID)) {
            perror("unshare");
            free(filtered_argv);
            return 1;
        }
    }

    child_proc = fork();
    if (child_proc == -1) {
        perror("fork");
        free(filtered_argv);
        return 1;
    }

    if (child_proc > 0) {
        wait(NULL);
        free(filtered_argv);
        return 0;
    }

    // Child process logic
    mkdir(args_info.base_dir_arg, 0777);
    {
        char mpl_db[PATH_MAX];
        snprintf(mpl_db, sizeof(mpl_db), "%s/mpl_db", args_info.base_dir_arg);
        mkdir(mpl_db, 0777);
    }

    setenv("ANDROID_DATA", "/data", 1);
    setenv("ANDROID_ROOT", "/system", 1);

    (void)envp;
    execve("/system/bin/main", argv, environ);
    perror("execve");
    free(filtered_argv);
    return 1;
}
