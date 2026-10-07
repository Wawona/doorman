/*
 * Session launch uses fork/exec; kept in C because Swift marks fork unavailable.
 */
#include <errno.h>
#include <grp.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "doorman_internal.h"

static void env_put(char **env, int *n, const char *key, const char *value) {
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s=%s", key, value ? value : "");
    env[(*n)++] = strdup(buf);
}

static char **build_login_env(const doorman_user_t *u, const doorman_session_t *session,
                              const char *runtime_dir) {
    char **env = calloc(16, sizeof(*env));
    if (!env) return NULL;
    int n = 0;
    if (u->name) env_put(env, &n, "USER", u->name);
    if (u->name) env_put(env, &n, "LOGNAME", u->name);
    if (u->home) env_put(env, &n, "HOME", u->home);
    env_put(env, &n, "SHELL", u->shell && u->shell[0] ? u->shell : "/bin/sh");
    env_put(env, &n, "PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin");
    env_put(env, &n, "XDG_RUNTIME_DIR", runtime_dir);
    if (session->type) env_put(env, &n, "XDG_SESSION_TYPE", session->type);
    if (session->id) env_put(env, &n, "XDG_SESSION_DESKTOP", session->id);
    if (session->type && strcmp(session->type, "wayland") == 0) {
        env_put(env, &n, "WAYLAND_DISPLAY", "wayland-0");
    }
    env[n] = NULL;
    return env;
}

doorman_result_t doorman_open_session(doorman_handle_t *handle,
                                      const doorman_session_t *session,
                                      pid_t *out_pid) {
    if (!handle || !session || !session->exec || !session->type || !out_pid) {
        return DOORMAN_ERR_INVALID_ARG;
    }
    if (!handle->authenticated) return DOORMAN_ERR_ABORT;
    if (!handle->user) return DOORMAN_ERR_USER_UNKNOWN;

    doorman_user_t u;
    if (doorman_lookup_user(handle->user, &u) != DOORMAN_SUCCESS) {
        return DOORMAN_ERR_USER_UNKNOWN;
    }

    int privileged = (geteuid() == 0);
    if (!privileged && u.uid != (uid_t)getuid()) {
        doorman_free_user_fields(&u);
        return DOORMAN_ERR_PERM;
    }

    char runtime_dir[64];
    snprintf(runtime_dir, sizeof(runtime_dir), "/private/tmp/doorman-%u", (unsigned)u.uid);
    char **child_env = build_login_env(&u, session, runtime_dir);
    const char *shell = (u.shell && u.shell[0]) ? u.shell : "/bin/sh";
    char *shell_dup = strdup(shell);
    char *exec_dup = strdup(session->exec);
    char *name_dup = u.name ? strdup(u.name) : NULL;
    char *home_dup = u.home ? strdup(u.home) : NULL;
    uid_t uid = u.uid;
    gid_t gid = u.gid;
    doorman_free_user_fields(&u);

    if (!shell_dup || !exec_dup || !child_env) {
        free(shell_dup);
        free(exec_dup);
        free(name_dup);
        free(home_dup);
        if (child_env) {
            for (int i = 0; child_env[i]; i++) free(child_env[i]);
            free(child_env);
        }
        return DOORMAN_ERR_SYSTEM;
    }

    pid_t pid = fork();
    if (pid < 0) {
        for (int i = 0; child_env[i]; i++) free(child_env[i]);
        free(child_env);
        free(shell_dup);
        free(exec_dup);
        free(name_dup);
        free(home_dup);
        return DOORMAN_ERR_SYSTEM;
    }
    if (pid == 0) {
        if (privileged) {
            setgid(gid);
            if (name_dup) initgroups(name_dup, (int)gid);
            setuid(uid);
            if (uid != 0 && setuid(0) == 0) _exit(127);
        }
        setsid();
        if (home_dup) chdir(home_dup);
        mkdir(runtime_dir, 0700);
        execle(shell_dup, shell_dup, "-l", "-c", exec_dup, (char *)NULL, child_env);
        _exit(127);
    }

    for (int i = 0; child_env[i]; i++) free(child_env[i]);
    free(child_env);
    free(shell_dup);
    free(exec_dup);
    free(name_dup);
    free(home_dup);

    handle->session_open = true;
    handle->session_pid = pid;
    *out_pid = pid;
    return DOORMAN_SUCCESS;
}

doorman_result_t doorman_close_session(doorman_handle_t *handle) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;
    if (!handle->session_open) return DOORMAN_ERR_NO_SESSION;
    handle->session_open = false;
    handle->session_pid = 0;
    return DOORMAN_SUCCESS;
}
