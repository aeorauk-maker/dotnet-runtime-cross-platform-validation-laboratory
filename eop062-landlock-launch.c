#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int add_path(int ruleset_fd, const char *path, uint64_t rights) {
    int path_fd = open(path, O_PATH | O_CLOEXEC);
    if (path_fd < 0 && errno == ENOENT) return 0;
    if (path_fd < 0) { perror(path); return -1; }
    struct landlock_path_beneath_attr rule = {
        .allowed_access = rights,
        .parent_fd = path_fd,
    };
    int rc = syscall(SYS_landlock_add_rule, ruleset_fd,
                     LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
    if (rc < 0) perror(path);
    close(path_fd);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: landlock-launch command [args...]\n"); return 2; }
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) { perror("landlock ABI unavailable"); return 77; }
    uint64_t ro = LANDLOCK_ACCESS_FS_EXECUTE |
                  LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    uint64_t rw_tmp = ro | LANDLOCK_ACCESS_FS_WRITE_FILE |
                      LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                      LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                      LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                      LANDLOCK_ACCESS_FS_MAKE_SYM;
    uint64_t handled = rw_tmp;
    if (abi >= 2) { handled |= LANDLOCK_ACCESS_FS_REFER; rw_tmp |= LANDLOCK_ACCESS_FS_REFER; }
    if (abi >= 3) { handled |= LANDLOCK_ACCESS_FS_TRUNCATE; rw_tmp |= LANDLOCK_ACCESS_FS_TRUNCATE; }
    struct landlock_ruleset_attr ruleset = {.handled_access_fs = handled};
    int ruleset_fd = syscall(SYS_landlock_create_ruleset, &ruleset,
                             sizeof(ruleset), 0);
    if (ruleset_fd < 0) { perror("landlock ruleset"); return 77; }
    if (add_path(ruleset_fd, "/usr", ro) < 0 ||
        add_path(ruleset_fd, "/lib", ro) < 0 ||
        add_path(ruleset_fd, "/lib64", ro) < 0 ||
        add_path(ruleset_fd, "/bin", ro) < 0 ||
        add_path(ruleset_fd, "/etc", ro) < 0 ||
        add_path(ruleset_fd, "/tmp", rw_tmp) < 0 ||
        add_path(ruleset_fd, "/dev/null", LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE) < 0 ||
        add_path(ruleset_fd, "/dev/urandom", LANDLOCK_ACCESS_FS_READ_FILE) < 0) {
        close(ruleset_fd); return 77;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("no new privileges"); close(ruleset_fd); return 77;
    }
    if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0) {
        perror("landlock restrict"); close(ruleset_fd); return 77;
    }
    close(ruleset_fd);
    if (chdir("/tmp") < 0) { perror("chdir /tmp"); return 77; }
    printf("LANDLOCK_ABI=%d LANDLOCK_READY=1 UID=%ld\n", abi, (long)geteuid());
    fflush(stdout);
    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 77;
}
