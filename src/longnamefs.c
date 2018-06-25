/*
 * Copyright © 2018  Rinat Ibragimov
 *
 * This file is part of longnamefs.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define FUSE_USE_VERSION 26
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "sha256.h"

// #define DDEBUG

#ifdef DDEBUG
#define logd(...) logd_impl(__func__, __VA_ARGS__)
#else
#define logd(...)                                                              \
    do {                                                                       \
        while (0) {                                                            \
            printf(__VA_ARGS__);                                               \
        }                                                                      \
    } while (0)
#endif

#define log_retval(expr) log_retval_impl(__func__, (expr))

#define MAX_NAME_LENGTH 4096

#define BACKEND_HASH_OCTET_COUNT  16
#define BACKEND_HASH_STRING_LENGTH (BACKEND_HASH_OCTET_COUNT * 2)

#define RETRY_ON_EINTR(x)                                                      \
    ({                                                                         \
        typeof(x) ___tmp_res;                                                  \
        do {                                                                   \
            ___tmp_res = (x);                                                  \
        } while (___tmp_res == -1 && errno == EINTR);                          \
        ___tmp_res;                                                            \
    })

typedef struct {
    /// File descriptor for the directory where file is or should be.
    int dirfd;

    /// Encoded file name.
    char fname[BACKEND_HASH_STRING_LENGTH + 1];

    /// Original file name.
    char raw_fname[MAX_NAME_LENGTH + 1];
} lnfs_path;

typedef struct {
    char *backend_path;
    int backend_fd;
} lnfs_configuration;

static lnfs_configuration lnfs_conf;

static struct fuse_opt lnfs_opts[] = {
    {"--backend %s", offsetof(lnfs_configuration, backend_path), 0},
    FUSE_OPT_END,
};

#ifdef DDEBUG
static void __attribute__((__format__(__printf__, 2, 3)))
logd_impl(const char *prefix, const char *fmt, ...)
{
    char buf[4096];
    va_list a;
    va_start(a, fmt);
    vsnprintf(buf, sizeof(buf), fmt, a);
    va_end(a);

    int tid = syscall(SYS_gettid);

    printf("%5d %s: %s\n", tid, prefix, buf);
}
#endif

static int
log_retval_impl(const char *prefix, int retval)
{
#ifdef DDEBUG
    logd_impl(prefix, "< %d", retval);
#endif
    return retval;
}

static void
strfreev(char **parts)
{
    for (char **part = parts; *part != NULL; part++)
        free(*part);

    free(parts);
}

static char **
strsplit(const char *str, char c)
{
    size_t nc = 0;
    for (const char *p = str; *p != '\0'; p++)
        nc += (*p == c);

    // N delimiters split a string into N + 1 parts. Plus one for
    // NULL-termination.
    char **const parts = calloc(sizeof(char *), nc + 2);
    if (parts == NULL)
        goto err_1;

    const char *start = str;
    size_t idx = 0;
    while (1) {
        const char *end = strchr(start, c);
        if (end == NULL) {
            parts[idx] = strdup(start);
            if (parts[idx] == NULL)
                goto err_2;
            break;
        }

        parts[idx] = strndup(start, end - start);
        if (parts[idx] == NULL)
            goto err_2;
        start = end + 1;
        idx += 1;
    }

    assert(idx + 1 == nc + 1);
    return parts;

err_2:
    strfreev(parts);

err_1:
    return NULL;
}

static size_t
strv_length(char **parts)
{
    size_t n = 0;
    for (char **part = parts; *part != NULL; part++)
        n += 1;

    return n;
}

// Converts path string into file descriptor of a directory and a file name in
// it.
static int
lnfs_open_path(const char *path, lnfs_path *p)
{
    char **const parts = strsplit(path, '/');
    if (parts == NULL)
        return -EIO;
    size_t const n = strv_length(parts);
    size_t const last_part_length = strlen(parts[n - 1]);
    if (last_part_length >= sizeof(p->raw_fname)) {
        strfreev(parts);
        return -ENAMETOOLONG;
    }

    int fd = openat(lnfs_conf.backend_fd, ".", O_PATH);
    if (fd < 0)
        return -errno;

    // All paths start with "/", so parts[0] will be always an empty string.
    for (size_t k = 1; k < n - 1; k++) {
        char encoded_name[BACKEND_HASH_STRING_LENGTH + 1];
        SHA256Data(parts[k], strlen(parts[k]), encoded_name,
                   BACKEND_HASH_OCTET_COUNT);

        int const prev_fd = fd;
        fd = openat(fd, encoded_name, O_PATH);
        int const saved_errno = errno;
        close(prev_fd);
        if (fd < 0) {
            strfreev(parts);
            return -saved_errno;
        }
    }

    p->dirfd = fd;
    SHA256Data(parts[n - 1], strlen(parts[n - 1]), p->fname,
               BACKEND_HASH_OCTET_COUNT);
    strncpy(p->raw_fname, parts[n - 1], last_part_length);
    p->raw_fname[last_part_length] = '\0';

    strfreev(parts);
    return 0;
}

static int
lnfs_open_paths(const char *path1, lnfs_path *p1, const char *path2,
                lnfs_path *p2)
{
    int const res1 = lnfs_open_path(path1, p1);
    if (res1 < 0)
        return res1;

    int const res2 = lnfs_open_path(path2, p2);
    if (res2 < 0) {
        close(p1->dirfd);
        return res2;
    }

    return 0;
}

static int
lnfs_write_namefile(const lnfs_path *p)
{
    char namefile_name[BACKEND_HASH_STRING_LENGTH + 2];
    memcpy(namefile_name, p->fname, BACKEND_HASH_STRING_LENGTH);
    memcpy(namefile_name + BACKEND_HASH_STRING_LENGTH, "n", 2);

    int const namefile_fd =
        openat(p->dirfd, namefile_name, O_WRONLY | O_CREAT, 0666);
    if (namefile_fd < 0)
        return -errno;

    ssize_t const raw_fname_len = strlen(p->raw_fname);
    ssize_t const written =
        RETRY_ON_EINTR(write(namefile_fd, p->raw_fname, raw_fname_len));
    int const ft_res = ftruncate(namefile_fd, written);
    close(namefile_fd);
    if (raw_fname_len != written || ft_res != 0)
        return -EIO;

    return 0;
}

static int
lnfs_remove_namefile(const lnfs_path *p)
{
    char namefile_name[BACKEND_HASH_STRING_LENGTH + 2];
    memcpy(namefile_name, p->fname, BACKEND_HASH_STRING_LENGTH);
    memcpy(namefile_name + BACKEND_HASH_STRING_LENGTH, "n", 2);

    unlinkat(p->dirfd, namefile_name, 0);
    // TODO: is it worth to check and report errors here? At the time this
    // function is called, file itself is deleted already.

    return 0;
}

static int
lnfs_access_impl(const char *path, int mask)
{
    if (strcmp(path, "/") == 0) {
        int const res = faccessat(lnfs_conf.backend_fd, ".", mask, 0);
        return (res < 0) ? -errno : 0;
    }

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const fa_res = faccessat(p.dirfd, p.fname, mask, AT_SYMLINK_NOFOLLOW);
    int const saved_errno = errno;
    close(p.dirfd);
    return (fa_res < 0) ? -saved_errno : 0;
}

static int
lnfs_access(const char *path, int mask)
{
    logd("> path=%s, mask=%d", path, mask);
    return log_retval(lnfs_access_impl(path, mask));
}

static int
lnfs_chmod_impl(const char *path, mode_t mode)
{
    if (strcmp(path, "/") == 0) {
        int const res = fchmod(lnfs_conf.backend_fd, mode & 0777);
        return (res < 0) ? -errno : 0;
    }

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const cm_res = fchmodat(p.dirfd, p.fname, mode & 0777, 0);
    int const cm_errno = errno;
    close(p.dirfd);
    return (cm_res < 0) ? -cm_errno : 0;
}

static int
lnfs_chmod(const char *path, mode_t mode)
{
    logd("> path=%s, mode=0%o", path, mode);
    return log_retval(lnfs_chmod_impl(path, mode));
}

static int
lnfs_chown_impl(const char *path, uid_t uid, gid_t gid)
{
    if (strcmp(path, "/") == 0) {
        int const co_res = fchown(lnfs_conf.backend_fd, uid, gid);
        return (co_res < 0) ? -errno : 0;
    }

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const co_res =
        fchownat(p.dirfd, p.fname, uid, gid, AT_SYMLINK_NOFOLLOW);
    int const co_errno = errno;
    close(p.dirfd);
    return (co_res < 0) ? -co_errno : 0;
}

static int
lnfs_chown(const char *path, uid_t uid, gid_t gid)
{
    logd("> path=%s, uid=%d, gid=%d", path, uid, gid);
    return log_retval(lnfs_chown_impl(path, uid, gid));
}

static int
lnfs_fsync_impl(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    int const fd = fi->fh;
    int const fs_res = isdatasync ? fdatasync(fd) : fsync(fd);
    return (fs_res < 0) ? -errno : 0;
}

static int
lnfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    logd("> path=%s, isdatasync=%d", path, isdatasync);
    return log_retval(lnfs_fsync_impl(path, isdatasync, fi));
}

static int
lnfs_getattr_impl(const char *path, struct stat *stbuf)
{
    if (strcmp(path, "/") == 0) {
        int const res = fstatat(lnfs_conf.backend_fd, "", stbuf, AT_EMPTY_PATH);
        return (res < 0) ? -errno : 0;
    }

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const s_res = fstatat(p.dirfd, p.fname, stbuf, AT_SYMLINK_NOFOLLOW);
    int const s_errno = errno;
    close(p.dirfd);
    return (s_res < 0) ? -s_errno : 0;
}

static int
lnfs_getattr(const char *path, struct stat *stbuf)
{
    logd("> path=%s", path);
    return log_retval(lnfs_getattr_impl(path, stbuf));
}

static void *
lnfs_init(struct fuse_conn_info *conn_info)
{
    logd(">");
    return NULL;
}

static int
lnfs_link_impl(const char *from, const char *to)
{
    if (strcmp(from, "/") == 0 || strcmp(to, "/") == 0)
        return -EFAULT;

    lnfs_path pfrom;
    lnfs_path pto;
    int const op_res = lnfs_open_paths(from, &pfrom, to, &pto);
    if (op_res < 0)
        return op_res;

    int const l_res = linkat(pfrom.dirfd, pfrom.fname, pto.dirfd, pto.fname, 0);
    int const l_errno = errno;
    if (l_res < 0) {
        close(pfrom.dirfd);
        close(pto.dirfd);
        return -l_errno;
    }

    int const wn_res = lnfs_write_namefile(&pto);

    close(pfrom.dirfd);
    close(pto.dirfd);
    return wn_res;
}

static int
lnfs_link(const char *from, const char *to)
{
    logd("> from=%s, to=%s", from, to);
    return log_retval(lnfs_link_impl(from, to));
}

static int
lnfs_mkdir_impl(const char *path, mode_t mode)
{
    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const md_res = mkdirat(p.dirfd, p.fname, mode);
    int const md_errno = errno;
    if (md_res < 0) {
        close(p.dirfd);
        return -md_errno;
    }

    int const wn_res = lnfs_write_namefile(&p);
    close(p.dirfd);
    return wn_res;
}

static int
lnfs_mkdir(const char *path, mode_t mode)
{
    logd("> path=%s, mode=0%o", path, mode);
    return log_retval(lnfs_mkdir_impl(path, mode));
}

static int
lnfs_mknod_impl(const char *path, mode_t mode, dev_t rdev)
{
    if (strcmp(path, "/") == 0)
        return -EFAULT;

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const mn_res = mknodat(p.dirfd, p.fname, mode, rdev);
    int const mn_errno = errno;
    if (mn_res < 0) {
        close(p.dirfd);
        return -mn_errno;
    }

    int const wn_res = lnfs_write_namefile(&p);
    close(p.dirfd);
    return wn_res;
}

static int
lnfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    logd("> path=%s, mode=0%o, dev=%zd", path, mode, rdev);
    return log_retval(lnfs_mknod_impl(path, mode, rdev));
}

static int
lnfs_open_or_create(const char *path, mode_t mode, unsigned int flags,
                    unsigned long int *out_fd)
{
    if (strcmp(path, "/") == 0) {
        int const fd = openat(lnfs_conf.backend_fd, ".", flags, mode & 0777);
        if (fd < 0)
            return -errno;

        *out_fd = fd;
        return 0;
    }

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const fd = openat(p.dirfd, p.fname, flags, mode & 0777);
    int const o_errno = errno;
    if (fd < 0) {
        close(p.dirfd);
        return -o_errno;
    }

    if (flags & O_CREAT) {
        int const wn_res = lnfs_write_namefile(&p);
        if (wn_res < 0) {
            close(p.dirfd);
            return wn_res;
        }
    }

    close(p.dirfd);

    *out_fd = fd;
    return 0;
}

static int
lnfs_open(const char *path, struct fuse_file_info *fi)
{
    logd("> path=%s", path);
    return log_retval(lnfs_open_or_create(path, 0, fi->flags, &fi->fh));
}

static int
lnfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    logd("> path=%s, mode=0%o", path, mode);
    return log_retval(
        lnfs_open_or_create(path, mode, fi->flags | O_CREAT, &fi->fh));
}

static int
lnfs_read_impl(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi)
{
    ssize_t const bytes_read = RETRY_ON_EINTR(pread(fi->fh, buf, size, offset));
    return (bytes_read < 0) ? -errno : bytes_read;
}

static int
lnfs_read(const char *path, char *buf, size_t size, off_t offset,
          struct fuse_file_info *fi)
{
    logd("> path=%s, buf=%p, size=%zu, offset=%zd", path, buf, size, offset);
    return log_retval(lnfs_read_impl(path, buf, size, offset, fi));
}

static int
lnfs_readdir_impl(const char *path, void *ctx, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *fi)
{
    int dirfd;

    if (strcmp(path, "/") == 0) {
        dirfd = openat(lnfs_conf.backend_fd, ".", O_RDONLY);
        if (dirfd < 0)
            return -errno;

    } else {
        lnfs_path p;
        int const op_res = lnfs_open_path(path, &p);
        if (op_res < 0)
            return op_res;

        dirfd = openat(p.dirfd, p.fname, O_RDONLY);
        int const o_errno = errno;
        close(p.dirfd);
        if (dirfd < 0)
            return -o_errno;
    }

    while (1) {
        char dirent_buf[8192];
        int nread =
            syscall(SYS_getdents64, dirfd, dirent_buf, sizeof(dirent_buf));
        if (nread < 0)
            goto err;

        if (nread == 0)
            break;

        int bpos = 0;
        while (bpos < nread) {
            struct linux_dirent64 {
                ino64_t d_ino;
                off64_t d_off;
                unsigned short d_reclen;
                unsigned char d_type;
                char d_name[];
            } de;

            memcpy(&de, dirent_buf + bpos, sizeof(de));

            char *const fname =
                dirent_buf + bpos + offsetof(struct linux_dirent64, d_name);

            do {
                size_t const fname_len = strlen(fname);
                if (fname_len != BACKEND_HASH_STRING_LENGTH + 1)
                    break;

                if (fname[BACKEND_HASH_STRING_LENGTH] != 'n')
                    break;

                int const name_fd = openat(dirfd, fname, O_RDONLY);
                if (name_fd < 0)
                    break;

                char real_name[MAX_NAME_LENGTH + 1];
                ssize_t const real_name_len =
                    RETRY_ON_EINTR(read(name_fd, real_name, MAX_NAME_LENGTH));
                close(name_fd);

                if (real_name_len <= 0)
                    break;

                real_name[real_name_len] = '\0';
                int const ret = filler(ctx, real_name, NULL, 0);
                if (ret != 0)
                    break;
            } while (0);

            bpos += de.d_reclen;
        }
    }

    close(dirfd);
    return 0;

err:
    close(dirfd);
    return -EIO;
}

static int
lnfs_readdir(const char *path, void *ctx, fuse_fill_dir_t filler, off_t offset,
             struct fuse_file_info *fi)
{
    logd("> path=%s", path);
    return log_retval(lnfs_readdir_impl(path, ctx, filler, offset, fi));
}

static int
lnfs_readlink_impl(const char *path, char *buf, size_t size)
{
    if (strcmp(path, "/") == 0)
        return -EINVAL;

    if (size == 0)
        return -EINVAL;

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    ssize_t const rl_res = readlinkat(p.dirfd, p.fname, buf, size);
    int const rl_errno = errno;
    close(p.dirfd);
    if (rl_res < 0)
        return -rl_errno;

    size_t const zt_pos = ((size_t)rl_res >= size) ? size - 1 : (size_t)rl_res;
    buf[zt_pos] = '\0';
    return 0;
}

static int
lnfs_readlink(const char *path, char *buf, size_t size)
{
    logd("> path=%s", path);
    return log_retval(lnfs_readlink_impl(path, buf, size));
}

static int
lnfs_release_impl(const char *path, struct fuse_file_info *fi)
{
    close(fi->fh);
    fi->fh = -1;
    return 0;
}

static int
lnfs_release(const char *path, struct fuse_file_info *fi)
{
    logd("> path=%s", path);
    return log_retval(lnfs_release_impl(path, fi));
}

static int
lnfs_rename_impl(const char *from, const char *to)
{
    if (strcmp(from, "/") == 0 || strcmp(to, "/") == 0)
        return -EFAULT;

    if (strcmp(from, to) == 0)
        return 0;

    lnfs_path pfrom;
    lnfs_path pto;
    int const op_res = lnfs_open_paths(from, &pfrom, to, &pto);
    if (op_res < 0)
        return op_res;

    int const rnm_res =
        renameat(pfrom.dirfd, pfrom.fname, pto.dirfd, pto.fname);
    int const rnm_errno = errno;
    if (rnm_res < 0) {
        close(pfrom.dirfd);
        close(pto.dirfd);
        return -rnm_errno;
    }

    int const wn_res = lnfs_write_namefile(&pto);
    if (wn_res < 0) {
        close(pfrom.dirfd);
        close(pto.dirfd);
        return wn_res;
    }

    int const rn_res = lnfs_remove_namefile(&pfrom);
    close(pfrom.dirfd);
    close(pto.dirfd);
    return rn_res;
}

static int
lnfs_rename(const char *from, const char *to)
{
    logd("> from=%s, to=%s", from, to);
    return log_retval(lnfs_rename_impl(from, to));
}

static int
lnfs_rmdir_impl(const char *path)
{
    if (strcmp(path, "/") == 0)
        return -EFAULT;

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const rd_res = unlinkat(p.dirfd, p.fname, AT_REMOVEDIR);
    int const rd_errno = errno;
    if (rd_res < 0) {
        close(p.dirfd);
        return -rd_errno;
    }

    int const wn_res = lnfs_remove_namefile(&p);
    close(p.dirfd);
    return wn_res;
}

static int
lnfs_rmdir(const char *path)
{
    logd("> path=%s", path);
    return log_retval(lnfs_rmdir_impl(path));
}

static int
lnfs_statfs_impl(const char *path, struct statvfs *stbuf)
{
    int const ret = fstatvfs(lnfs_conf.backend_fd, stbuf);
    return (ret < 0) ? -errno : 0;
}

static int
lnfs_statfs(const char *path, struct statvfs *stbuf)
{
    logd("> path=%s", path);
    return log_retval(lnfs_statfs_impl(path, stbuf));
}

static int
lnfs_symlink_impl(const char *from, const char *to)
{
    if (strcmp(to, "/") == 0)
        return -EINVAL;

    lnfs_path p;
    int op_res = lnfs_open_path(to, &p);
    if (op_res < 0)
        return op_res;

    int const sl_res = symlinkat(from, p.dirfd, p.fname);
    int sl_errno = errno;
    if (sl_res < 0) {
        close(p.dirfd);
        return -sl_errno;
    }

    int const wn_res = lnfs_write_namefile(&p);
    close(p.dirfd);
    return wn_res;
}

static int
lnfs_symlink(const char *from, const char *to)
{
    logd("> from=%s, to=%s", from, to);
    return log_retval(lnfs_symlink_impl(from, to));
}

static int
lnfs_truncate_impl(const char *path, off_t size)
{
    if (strcmp(path, "/") == 0)
        return -EFAULT;

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const fd = openat(p.dirfd, p.fname, O_WRONLY);
    int const o_errno = errno;
    if (fd < 0) {
        close(p.dirfd);
        return -o_errno;
    }

    int const ft_res = ftruncate(fd, size);
    int const ft_errno = errno;
    close(fd);
    close(p.dirfd);
    return (ft_res < 0) ? -ft_errno : 0;
}

static int
lnfs_truncate(const char *path, off_t size)
{
    logd("> path=%s, size=%zd", path, size);
    return log_retval(lnfs_truncate_impl(path, size));
}

static int
lnfs_unlink_impl(const char *path)
{
    if (strcmp(path, "/") == 0)
        return -EFAULT;

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const ul_res = unlinkat(p.dirfd, p.fname, 0);
    int const ul_errno = errno;
    if (ul_res < 0) {
        close(p.dirfd);
        return -ul_errno;
    }

    int const rn_res = lnfs_remove_namefile(&p);
    close(p.dirfd);
    return rn_res;
}

static int
lnfs_unlink(const char *path)
{
    logd("> path=%s", path);
    return log_retval(lnfs_unlink_impl(path));
}

static int
lnfs_utimens_impl(const char *path, const struct timespec ts[2])
{
    if (strcmp(path, "/") == 0) {
        int const res = futimens(lnfs_conf.backend_fd, ts);
        return (res < 0) ? -errno : 0;
    }

    lnfs_path p;
    int const op_res = lnfs_open_path(path, &p);
    if (op_res < 0)
        return op_res;

    int const ut_res = utimensat(p.dirfd, p.fname, ts, AT_SYMLINK_NOFOLLOW);
    int const ut_errno = errno;
    close(p.dirfd);
    return (ut_res < 0) ? -ut_errno : 0;
}

static int
lnfs_utimens(const char *path, const struct timespec ts[2])
{
    logd("> path=%p, ts[2]={{%zd,%zd},{%zd,%zd}}", path, (ssize_t)ts[0].tv_sec,
         ts[0].tv_nsec, (ssize_t)ts[1].tv_sec, ts[1].tv_nsec);
    return log_retval(lnfs_utimens_impl(path, ts));
}

static int
lnfs_write_impl(const char *path, const char *buf, size_t size, off_t offset,
                struct fuse_file_info *fi)
{
    ssize_t const written = RETRY_ON_EINTR(pwrite(fi->fh, buf, size, offset));
    return (written < 0) ? -errno : written;
}

static int
lnfs_write(const char *path, const char *buf, size_t size, off_t offset,
           struct fuse_file_info *fi)
{
    logd("> path=%s, buf=%p, size=%zu, offset=%zd", path, buf, size, offset);
    return log_retval(lnfs_write_impl(path, buf, size, offset, fi));
}

static struct fuse_operations lnfs_operations = {
    .access = lnfs_access,
    .chmod = lnfs_chmod,
    .chown = lnfs_chown,
    .create = lnfs_create,
    .fsync = lnfs_fsync,
    .getattr = lnfs_getattr,
    .init = lnfs_init,
    .link = lnfs_link,
    .mkdir = lnfs_mkdir,
    .mknod = lnfs_mknod,
    .open = lnfs_open,
    .read = lnfs_read,
    .readdir = lnfs_readdir,
    .readlink = lnfs_readlink,
    .release = lnfs_release,
    .rename = lnfs_rename,
    .rmdir = lnfs_rmdir,
    .statfs = lnfs_statfs,
    .symlink = lnfs_symlink,
    .truncate = lnfs_truncate,
    .unlink = lnfs_unlink,
    .utimens = lnfs_utimens,
    .write = lnfs_write,
};

int
main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (fuse_opt_parse(&args, &lnfs_conf, lnfs_opts, NULL) != 0) {
        fprintf(stderr, "longnamefs: failed to parse arguments\n");
        return 2;
    }

    if (lnfs_conf.backend_path == NULL) {
        fprintf(stderr,
                "longnamefs: no backend directory specified (--backend)\n");
        return 2;
    }

    lnfs_conf.backend_fd = open(lnfs_conf.backend_path, O_RDONLY);
    if (lnfs_conf.backend_fd < 0) {
        fprintf(stderr, "longnamefs: can't open backend directory (%s)\n",
                lnfs_conf.backend_path);
        return 1;
    }

    logd("lnfs_conf.backend_fd = %d", lnfs_conf.backend_fd);

    int const fuse_main_res =
        fuse_main(args.argc, args.argv, &lnfs_operations, NULL);
    logd("fuse_main -> %d", fuse_main_res);

    fuse_opt_free_args(&args);
    close(lnfs_conf.backend_fd);

    return fuse_main_res;
}
