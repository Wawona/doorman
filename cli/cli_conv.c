#include "../doorman/include/doorman.h"

int doorman_cli_conv(int num_msg,
                     const doorman_message_t **msg,
                     doorman_response_t **resp,
                     void *appdata);

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static char *read_secret(const char *prompt) {
    if (prompt) {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    struct termios oldt, newt;
    int is_tty = tcgetattr(STDIN_FILENO, &oldt) == 0;
    if (is_tty) {
        newt = oldt;
        newt.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);

    if (is_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        fputc('\n', stderr);
    }

    if (n <= 0) {
        free(line);
        return NULL;
    }
    if (line[n - 1] == '\n') {
        line[n - 1] = '\0';
    }
    return line;
}

static char *read_line_raw(const char *prompt) {
    if (prompt) {
        fputs(prompt, stderr);
        fflush(stderr);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);
    if (n <= 0) {
        free(line);
        return NULL;
    }
    if (line[n - 1] == '\n') {
        line[n - 1] = '\0';
    }
    return line;
}

int doorman_cli_conv(int num_msg,
                     const doorman_message_t **msg,
                     doorman_response_t **resp,
                     void *appdata) {
    (void)appdata;
    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->style) {
        case DOORMAN_PROMPT_ECHO_OFF:
            resp[i]->resp = read_secret(msg[i]->msg);
            if (!resp[i]->resp) {
                return 1;
            }
            break;
        case DOORMAN_PROMPT_ECHO_ON:
            resp[i]->resp = read_line_raw(msg[i]->msg);
            if (!resp[i]->resp) {
                return 1;
            }
            break;
        case DOORMAN_ERROR_MSG:
            if (msg[i]->msg) {
                fprintf(stderr, "%s\n", msg[i]->msg);
            }
            break;
        case DOORMAN_TEXT_INFO:
            if (msg[i]->msg) {
                printf("%s\n", msg[i]->msg);
            }
            break;
        default:
            break;
        }
    }
    return 0;
}
