#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Struttura temporanea per mantenere i dati della rete analizzata al momento
struct WifiCell {
    char bssid[32];
    char ssid[256];
    char signal[32];
    char channel[32];
    int has_wep;
    int has_wpa;
    int has_wpa2;
};

// Rimuove spazi, tabulazioni e ritorni a capo (usata per BSSID, Canale e Segnale)
void trim_all(char *str) {
    char *src = str, *dst = str;
    while (*src) {
        if (*src != ' ' && *src != '\t' && *src != '\r' && *src != '\n') {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

// Protegge i caratteri speciali all'interno del nome dell'SSID per evitare JSON corrotto
void escape_ssid(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j < dst_size - 2; i++) {
        if (src[i] == '\\' || src[i] == '"') {
            dst[j++] = '\\'; // Aggiunge il backslash di escape
        }
        if (src[i] != '\r' && src[i] != '\n') {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

// Stampa la cella corrente trasformandola in oggetto JSON
void emit_cell(const struct WifiCell *cell, int *is_first) {
    if (!*is_first) {
        printf(",");
    }
    *is_first = 0;

    // Logica di classificazione sicurezza identica al vecchio script
    const char *sec = "0";
    if (cell->has_wpa && cell->has_wpa2) sec = "6";
    else if (cell->has_wpa2) sec = "3";
    else if (cell->has_wpa)  sec = "2";
    else if (cell->has_wep)  sec = "1";

    char escaped_ssid[512] = {0};
    escape_ssid(cell->ssid, escaped_ssid, sizeof(escaped_ssid));

    printf("{\"bssid\":\"%s\",\"ssid\":\"%s\",\"signal\":\"%s\",\"channel\":\"%s\",\"security\":\"%s\"}",
           cell->bssid, escaped_ssid, cell->signal, cell->channel, sec);
}

int main() {
    // Esegue il comando iwlist e cattura lo standard output in streaming
    FILE *fp = popen("iwlist ath0 scan 2>/dev/null", "r");
    if (!fp) {
        printf("[]\n");
        return 0;
    }

    char line[512];
    struct WifiCell current_cell;
    int has_cell = 0;
    int is_first = 1;

    // Inizializzazione della prima struttura
    memset(&current_cell, 0, sizeof(current_cell));
    strcpy(current_cell.signal, "0");
    strcpy(current_cell.channel, "0");

    printf("["); // Apertura array JSON

    while (fgets(line, sizeof(line), fp)) {

        // 1. Rilevamento Nuova Cella (Nuova Rete)
        if (strstr(line, "Cell ")) {
            if (has_cell) {
                emit_cell(&current_cell, &is_first);
            }
            memset(&current_cell, 0, sizeof(current_cell));
            strcpy(current_cell.signal, "0");
            strcpy(current_cell.channel, "0");
            has_cell = 1;

            // Estrazione BSSID (Address:)
            char *addr_ptr = strstr(line, "Address:");
            if (addr_ptr) {
                strncpy(current_cell.bssid, addr_ptr + 8, sizeof(current_cell.bssid) - 1);
                trim_all(current_cell.bssid);
            }
        }
        else if (has_cell) {
            // 2. Estrazione ESSID
            char *essid_ptr = strstr(line, "ESSID:\"");
            if (essid_ptr) {
                char *start = essid_ptr + 7;
                char *end = strchr(start, '"');
                if (end) {
                    size_t len = end - start;
                    if (len >= sizeof(current_cell.ssid)) len = sizeof(current_cell.ssid) - 1;
                    strncpy(current_cell.ssid, start, len);
                    current_cell.ssid[len] = '\0';
                }
            }

            // 3. Estrazione Canale (Formato standard "Channel:X")
            char *chan_ptr = strstr(line, "Channel:");
            if (chan_ptr && !strstr(line, "Frequency")) {
                char *p = chan_ptr + 8;
                char tmp_chan[32] = {0};
                int idx = 0;
                while (*p && isdigit((unsigned char)*p) && idx < 31) {
                    tmp_chan[idx++] = *p++;
                }
                if (idx > 0) strcpy(current_cell.channel, tmp_chan);
            }

            // 4. Estrazione Canale (Formato alternativo "Channel X")
            char *chan_ptr2 = strstr(line, "Channel ");
            if (chan_ptr2 && strcmp(current_cell.channel, "0") == 0) {
                char *p = chan_ptr2 + 8;
                char tmp_chan[32] = {0};
                int idx = 0;
                while (*p && isdigit((unsigned char)*p) && idx < 31) {
                    tmp_chan[idx++] = *p++;
                }
                if (idx > 0) strcpy(current_cell.channel, tmp_chan);
            }

            // 5. Estrazione Livello Segnale (Gestisce sia dBm negativi che valori in percentuale)
            char *sig_ptr = strstr(line, "Signal level");
            if (sig_ptr) {
                char *p = sig_ptr + 12;
                while (*p && *p != '=' && *p != ':') p++;
                if (*p == '=' || *p == ':') {
                    p++;
                    while (*p == ' ') p++; // Salta spazi vuoti
                    char tmp_sig[32] = {0};
                    int idx = 0;
                    if (*p == '-') tmp_sig[idx++] = *p++; // Mantiene il segno meno
                    while (*p && (isdigit((unsigned char)*p) || *p == '/') && idx < 31) {
                        tmp_sig[idx++] = *p++;
                    }
                    if (idx > 0) {
                        strcpy(current_cell.signal, tmp_sig);
                        trim_all(current_cell.signal);
                    }
                }
            }

            // 6. Flags di Sicurezza
            if (strstr(line, "Encryption key:on")) {
                current_cell.has_wep = 1;
            }
            if (strstr(line, "IE: IEEE 802.11i/WPA2")) {
                current_cell.has_wpa2 = 1;
            }
            if (strstr(line, "IE: WPA Version")) {
                current_cell.has_wpa = 1;
            }
        }
    }

    // Emette l'ultima cella rimasta in memoria prima della chiusura
    if (has_cell) {
        emit_cell(&current_cell, &is_first);
    }

    printf("]\n"); // Chiusura array JSON
    pclose(fp);
    return 0;
}
