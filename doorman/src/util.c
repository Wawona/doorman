/*
 * util.m - small, dependency-free helpers shared across the backends:
 * strict name validation and a constant-time byte comparison. Both are
 * security primitives, kept in one place so their behaviour is easy to audit.
 */

#include <stddef.h>
#include <stdbool.h>
#include "doorman_internal.h"

/* Longest short name we are willing to interpolate into a path or argv. */
#define DM_NAME_MAX 244

bool _dm_name_ok(const char *name) {
    if (!name) return false;

    size_t len = strnlen(name, DM_NAME_MAX + 1);
    if (len == 0 || len > DM_NAME_MAX) return false;

    /* A leading '-' could be mistaken for an option by a downstream tool; a
     * leading '.' invites "." / ".." path shenanigans in the dsLocal reader. */
    if (name[0] == '-' || name[0] == '.') return false;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        bool allowed = (c >= 'A' && c <= 'Z') ||
                       (c >= 'a' && c <= 'z') ||
                       (c >= '0' && c <= '9') ||
                       c == '_' || c == '-' || c == '.';
        if (!allowed) return false;
    }
    return true;
}

const char *doorman_strerror(doorman_result_t result) {
    switch (result) {
        case DOORMAN_SUCCESS:           return "success";
        case DOORMAN_ERR_AUTH:          return "authentication failed";
        case DOORMAN_ERR_USER_UNKNOWN:  return "unknown user";
        case DOORMAN_ERR_ACCT_DISABLED: return "account is disabled or expired";
        case DOORMAN_ERR_PERM:          return "insufficient privileges";
        case DOORMAN_ERR_CONV:          return "conversation error";
        case DOORMAN_ERR_ABORT:         return "transaction aborted";
        case DOORMAN_ERR_NO_SESSION:    return "no such session";
        case DOORMAN_ERR_SYSTEM:        return "system error";
        case DOORMAN_ERR_INVALID_ARG:   return "invalid argument";
        case DOORMAN_ERR_UNSUPPORTED:   return "operation not supported";
    }
    return "unknown error";
}

void _dm_scrub_free(char **slot, size_t len) {
    if (slot && *slot) {
        _dm_scrub(*slot, len);
        free(*slot);
        *slot = NULL;
    }
}

bool _dm_consttime_equal(const void *a, const void *b, size_t len) {
    if (!a || !b) return false;
    const volatile unsigned char *pa = (const volatile unsigned char *)a;
    const volatile unsigned char *pb = (const volatile unsigned char *)b;
    unsigned char accum = 0;
    for (size_t i = 0; i < len; i++)
        accum = (unsigned char)(accum | (unsigned char)(pa[i] ^ pb[i]));
    return accum == 0;
}
