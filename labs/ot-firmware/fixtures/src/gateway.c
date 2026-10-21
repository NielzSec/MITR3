/*
 * gateway.c — synthetic OT gateway CGI for the MITR3 firmware lab.
 *
 * Deliberately vulnerable build (v1): trusts an X-Lab-Admin header as proof of
 * authorization. The fixed build (v2) removes the header path and validates a
 * session token on disk. Same call graph, one trust-boundary change — which is
 * exactly the kind of delta the lab teaches you to isolate.
 *
 * Build: gcc -O2 -s -o status.cgi gateway.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_HEADERS 4096

static int read_request(char *buf, size_t cap) {
    size_t n = fread(buf, 1, cap - 1, stdin);
    if (n == 0) return -1;
    buf[n] = '\0';
    return 0;
}

static int header_has(const char *headers, const char *needle) {
    return strstr(headers, needle) != NULL;
}

static int token_valid(const char *token) {
    FILE *fp = fopen("/var/run/lab-session", "r");
    char expected[128];
    if (!fp) return 0;
    if (!fgets(expected, sizeof(expected), fp)) { fclose(fp); return 0; }
    fclose(fp);
    expected[strcspn(expected, "\r\n")] = '\0';
    return strcmp(expected, token) == 0;
}

/* Trust boundary lives here. v1 has a debug bypass, v2 does not. */
static int authorize(const char *path, const char *headers) {
#ifdef LAB_V1
    if (header_has(headers, "X-Lab-Admin: 1")) {
        return 1; /* backdoor: client-controlled header grants admin */
    }
#endif
    if (strncmp(path, "/admin", 6) == 0) {
        const char *tok = strstr(headers, "X-Session: ");
        if (!tok) return 0;
        tok += 11;
        char value[128];
        size_t i = 0;
        while (tok[i] && tok[i] != '\r' && tok[i] != '\n' && i < sizeof(value) - 1) {
            value[i] = tok[i];
            i++;
        }
        value[i] = '\0';
        return token_valid(value);
    }
    return 1;
}

static void render(const char *path, int allowed) {
    printf("Content-Type: text/html\r\n\r\n");
    printf("<html><body><h1>Lab Gateway</h1><p>path=%s</p>", path);
    printf("<p>%s</p>", allowed ? "authorized" : "denied");
    if (allowed && strncmp(path, "/admin", 6) == 0) {
        printf("<pre>firmware=2.4.1\nserial=LAB-0001\nmode=service</pre>");
    }
    printf("</body></html>\n");
}

int main(void) {
    char buf[MAX_HEADERS];
    if (read_request(buf, sizeof(buf)) != 0) {
        printf("Status: 400 Bad Request\r\n\r\n");
        return 1;
    }
    char path[256] = "/";
    const char *line_end = strstr(buf, "\r\n");
    if (line_end) {
        const char *sp1 = strchr(buf, ' ');
        if (sp1) {
            const char *sp2 = strchr(sp1 + 1, ' ');
            if (sp2 && sp2 > sp1 + 1 && (size_t)(sp2 - sp1 - 1) < sizeof(path)) {
                memcpy(path, sp1 + 1, (size_t)(sp2 - sp1 - 1));
                path[sp2 - sp1 - 1] = '\0';
            }
        }
    }
    render(path, authorize(path, buf));
    return 0;
}
