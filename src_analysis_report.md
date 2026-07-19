# Analisi dei Programmi C e Script Shell (directory `src`)

Questo report illustra il funzionamento dei programmi e script sviluppati in `src` per la modifica del firmware di un router TP-LINK. Il sistema si basa su una combinazione di strumenti per lanciare attacchi "Evil Twin" con deautenticazione e per la gestione di un Captive Portal malevolo allo scopo di intercettare le credenziali degli utenti (IoT Security Project).

Di seguito viene spiegato il comportamento generale di ogni programma, accompagnato dall'elenco delle sue funzioni e dal relativo ruolo.

---

## 1. `captive_portal.c`

### Funzionamento Generale
Questo programma implementa un Captive Portal malevolo progettato per essere eseguito sul router. Si occupa di intercettare il traffico web (HTTP e HTTPS) generato dai client connessi e deviarlo verso la pagina di login servita dallo stesso router. Il suo scopo principale è ingannare l'utente affinché immetta una password (le credenziali) prima di sbloccare la connessione ad internet. 

Per farlo, modifica le regole di instradamento di `iptables` sfruttando il DNAT (Destination NAT) e avvia uno spoofing DNS (tramite l'eseguibile `dnsd`) in modo da deviare qualsiasi richiesta al nome a dominio. Qualsiasi navigazione redirigerà l'utente al server web locale servito sulla porta 8081.

### Elenco Funzioni

*   `url_decode(char *dst, const char *src)`: Prende in input una stringa e decodifica tutti i caratteri speciali URL-encoded (es. `%20` convertito in spazio ` `). Serve per pulire i dati inviati dai client.
*   `get_param(const char *data, const char *name, char *val, int max)`: Funzione di utilità per parsare il corpo di una richiesta POST (o query string) ed estrarre il valore di un dato parametro (ad esempio, recuperare il campo password `p`).
*   `read_file(const char *path)`: Apre il file specificato, ne legge l'intero contenuto calcolandone prima la grandezza, alloca la memoria dinamicamente e lo restituisce sotto forma di stringa.
*   `send_response(int fd, const char *status, const char *ctype, const char *body)`: Compone gli header necessari e risponde alla richiesta HTTP del client (inviando status code, content-type e il payload HTML).
*   `is_authorized(const char *ip)`: Legge il file `/tmp/authorized_clients` per verificare se l'indirizzo IP di un client è già stato autorizzato e quindi debba bypassare la deviazione del traffico.
*   `authorize_ip(const char *ip)`: Inserisce un IP nella lista dei client autorizzati. Esegue inoltre un comando di sistema per aggiungere in cima alla catena `CAPTIVE` di iptables una regola `RETURN` per quell'IP, liberando il client dal DNAT e lasciandolo navigare.
*   `get_router_ip(char *out, size_t out_len)`: Sfrutta le chiamate API dirette del kernel (`ioctl` e socket) per reperire l'indirizzo IP dell'interfaccia di rete locale del router (`br0`), evitando subshell.
*   `setup_iptables(const char *router_ip)`: Configura il firewall del router. Svuota le catene preesistenti e indirizza tutto il traffico (TCP/UDP su porte 53, 80 e 443) intercettato in PREROUTING verso gli indirizzi ed i servizi di attacco (server DNS e server web malevolo).
*   `serve_portal(int fd)`: Invia al client i file HTML del captive portal presi in `/etc/portal/template.html` o un template hardcoded di fallback, che mostra un avviso di autenticazione necessaria in base all'SSID.
*   `main(void)`: Costituisce l'entry-point del software. Usa `fork()` e `setsid()` per separarsi in un processo demone (background). Attende l'acquisizione dell'IP del router, configura il file e lancia `dnsd` (per lo spoofing DNS), configura l'intercettazione con `setup_iptables` e apre un loop di ascolto (socket server) sulla porta HTTP (8081). Se un utente compie una richiesta POST su `/connect`, salva i dati nel log `/tmp/creds.log` e lo autorizza alla rete.

---

## 2. `deauth.c`

### Funzionamento Generale
Questo programma svolge il compito di sferrare un attacco di **Deauthentication** (Deautenticazione). Sfruttando raw sockets di livello link (`AF_PACKET`), genera e trasmette pacchetti di Management 802.11 contraffatti. L'invio di tali frame fa disconnettere di forza uno o tutti i client della rete dell'Access Point bersaglio. Può funzionare sia interfacciandosi con un header "radiotap" per schede moderne, sia iniettando frame nudi per i chip Atheros molto usati in ambienti embedded (es. driver Madwifi su MIPS). Non richiede librerie di appoggio esterne come `libpcap`.

### Elenco Funzioni

*   `parse_mac(const char *str, unsigned char mac[6])`: Prende in input la rappresentazione in formato testo di un MAC Address (`AA:BB:CC:DD:EE:FF`) e la scompone traducendola nell'array di 6 byte esadecimali associato.
*   `build_deauth_frame(unsigned char *buf, const unsigned char bssid[6], const unsigned char client[6], unsigned short reason, unsigned short seq)`: Funzione centrale per comporre byte per byte l'esatto payload di un frame WiFi (802.11) di "Deauthentication". Inserisce un header Radiotap minimo, regola i campi "Frame Control" (indicando sottotipo 12), e posiziona nei campi `Address1`, `Address2` e `Address3` l'indirizzo della vittima e l'AP bersaglio per ingannare la rete.
*   `get_ifindex(int sockfd, const char *ifname)`: Interroga il kernel per l'indice di un'interfaccia di rete a partire dalla stringa passata, essenziale per la configurazione del socket Raw e la specificazione di invio su quello specifico hardware.
*   `print_usage(const char *progname)`: Stampa il banner di guida che informa l'utente sui parametri da passare all'avvio. Spiega anche l'uso del flag `--no-radiotap`.
*   `main(int argc, char *argv[])`: Il ciclo principale analizza gli argomenti d'ingresso, apre il socket `AF_PACKET` di basso livello (richiede i permessi di root) e in un ciclo `for` emette i pacchetti avvelenati usando `sendto`. Ha un leggero sleep per non saturare i driver.

---

## 3. `micro_httpd.c`

### Funzionamento Generale
Rappresenta un micro-server Web di Comando & Controllo, sviluppato appositamente per le scarse risorse di un router embedded (C nativo). Rimane in ascolto sulla porta `8080` (diversa dal captive portal) e funge da "backend" invisibile per permettere agli attaccanti (o a una interfaccia web client di controllo) di inviare comandi al router. Espone vari "endpoint" (API) per innescare gli attacchi, recuperare le password rubate ed effettuare cambiamenti alle impostazioni Wi-Fi come lo spoofing dell'SSID. 

### Elenco Funzioni

*   `url_decode(char *dst, const char *src)`: Speculare a quella presente nel captive portal, decodifica il testo dai caratteri escape HTML inviati durante la sottomissione di form web e parametri HTTP.
*   `get_param(const char *data, const char *name, char *val_buf, int max_len)`: Utilità per estrarre il contenuto delle Query String (per GET requests) o dei parametri x-www-form-urlencoded dalle POST request per trovare variabili precise in stringhe complesse.
*   `read_file(const char *path)`: Semplice helper function per acquisire, in memoria, stringhe testuali complete dal filesystem (spesso usata per recuperare `/tmp/portal_ssid` o i file di log).
*   `write_file(const char *path, const char *content)`: Sovrascrive o crea file di testo nel sistema inserendo la stringa di input. È necessaria per aggiornare la configurazione real-time.
*   `send_response(int client_fd, const char *status, const char *content_type, const char *body, const char *extra_headers)`: Assembla una corretta risposta server con tanto di status-code HTTP e Content-Type personalizzato, poi la trasmette al client usando `send()`.
*   `run_command_output(const char *cmd)`: Apre un processo tramite la chiamata POSIX `popen()`, esegue uno script shell nel sistema operativo, ne assorbe l'output testuale da `stdout` usando memoria riallocata (`realloc()`) in loop per adattarsi a risposte di dimensione imprevista, e chiude il task.
*   `main()`: Gestisce l'apertura e binding del socket TCP del server. Gestisce un loop di `accept` in cui riceve le richieste di routing in entrata, che sono le seguenti:
    *   `/set_ssid`: Recupera l'input, lo sanifica filtrando stringhe malevole o anomale e passa il nuovo SSID al binario `/usr/bin/additional/set_ssid` lanciato in background.
    *   `/get_ssid`: API per leggere il nome Wi-Fi attuale dal server file e risponderlo in text/plain.
    *   `/set_target`: Permette di definire BSSID (MAC bersaglio) e Canale target, registrandoli in specifici file temporanei usati poi dagli altri script.
    *   `/deauth`: Assorbe tutti i parametri e avvia, usando una `system()`, il deauth background process appoggiandosi all'eseguibile di `deauth.c`.
    *   `/deauth_stop`: Rileva il Process ID dell'attacco di deautenticazione corrente (`/tmp/deauth.pid`) e lo termina (SIGKILL).
    *   `/deauth_status`: Recupera dati assortiti dall'attacco e le ultime 20 righe del suo log tramite comando shell (`tail`).
    *   `/creds`: Accesso privato alle credenziali. Solo se il richiedente fornisce la password via query string (es. `?p=admin`) restituisce il payload del file in cui sono stoccate.

---

## 4. `set_ssid` (Script Shell)

### Funzionamento Generale
Scritto in bash/sh, è lo script che si occupa di modificare sul router l'SSID del punto di accesso finto (Evil Twin). Usa utility di rete specifiche dell'ambiente embedded (`brctl`, `iwconfig`, `wlanconfig`) che presuppongono una particolare architettura driver di sistema (nello specifico i driver hardware WiFi "Atheros").

### Elenco Flusso e Comandi

Lo script non contiene "funzioni" isolate (essendo estremamente breve), ma esegue in sequenza un flusso di operazioni critiche a livello di sistema operativo per azzerare e riconfigurare l'interfaccia di rete senza dover riavviare l'intero router:

1.  **Chiusura demone**: Verifica tramite greping dei processi (`ps`) se il demone Access Point nativo (`hostapd`) è attivo e lo termina violentemente con un `kill`.
2.  **Smontaggio dell'interfaccia `ath0`**: L'interfaccia Wi-Fi `ath0` viene portata nello stato down (`ifconfig ath0 down`).
3.  **Distacco dal Bridge**: Utilizza il tool bridge-control (`brctl delif br0 ath0`) per dissociare l'AP dal bridge della rete locale del router.
4.  **Distruzione Virtual AP**: Rimuove completamente l'interfaccia virtuale `ath0` associata usando gli specifici tool dei driver Atheros (`wlanconfig ath0 destroy`). Questo serve ad eludere qualsiasi configurazione pre-programmata non facilmente bypassabile.
5.  **Re-inizializzazione AP**: Crea una nuova interfaccia `ath0` ex-novo come Virtual Access Point e la aggancia allo strato Hardware reale `wifi0` (`wlanconfig ath0 create ...`).
6.  **Configurazione SSID**: Applica il nuovo ESSID iniettando come primo parametro in input il testo desiderato all'utility standard di manipolazione wireless (`iwconfig ath0 essid "$1"`).
7.  **Ri-associazione Bridge e Accensione**: Rimette `ath0` nel bridge e tira "su" la porta (`ifconfig ath0 up`) finalizzando e attivando così la rete col finto nome.

---

## Approfondimenti Tecnici

### Il Ruolo del Firewall (iptables e NAT)
L'implementazione del Captive Portal si affida integralmente a `iptables` (l'interfaccia a Netfilter, il motore firewall del kernel Linux). Questa scelta architetturale risponde a due esigenze fondamentali:
*   **Intercettazione Trasparente (DNAT)**: Un Web Server locale in C non riceverebbe mai i pacchetti destinati a un server esterno (es. Google). È necessario che il firewall, operando a livello di rete, intercetti i pacchetti in transito e ne sovrascriva al volo l'indirizzo di destinazione (tecnica **Destination NAT** o DNAT), forzandone l'instradamento verso la porta 8081 del server malevolo in modo totalmente invisibile al client.
*   **Efficienza**: L'elaborazione e la manipolazione dei pacchetti svolta dal Kernel Linux garantisce velocità massime con il minor impiego possibile di CPU e RAM, caratteristica imprescindibile per l'hardware limitato dei dispositivi IoT (router TP-LINK).

### Il Meccanismo di "Sblocco" (authorize_ip)
Quando la vittima inserisce la password, il programma invoca la funzione `authorize_ip`, che agisce per ripristinare la normale connettività internet:
1.  **Persistenza**: Salva l'IP in `/tmp/authorized_clients` in modalità append, tenendo traccia degli accessi ed evitando l'aggiunta di regole iptables duplicate.
2.  **Bypass del DNAT (La regola RETURN)**: Inietta dinamicamente una nuova regola nel firewall (`iptables -t nat -I CAPTIVE 1 -s <IP_CLIENT> -j RETURN`). L'opzione `-I ... 1` la pone in cima a tutte le regole. Quando l'utente sbloccato naviga, il firewall elabora questa regola per prima: l'azione `RETURN` causa un'uscita immediata dalla catena `CAPTIVE`. Il pacchetto salta perciò le regole di reindirizzamento (DNAT) posizionate in basso e viaggia regolarmente verso la rete esterna.

### Struttura di un Frame di Deauthentication (802.11)
Il frame di Deauthentication è un pacchetto di *Management* (gestione) previsto dallo standard Wi-Fi (802.11) per disconnettere un client in modo legittimo. Essendo intrinsecamente non crittografato e privo di controlli di autenticità (fino all'introduzione del WPA3/PMF), può essere facilmente falsificato (spoofed) da un attaccante. 

La sua struttura a basso livello (costruita manualmente in `deauth.c`) è sequenzialmente formata dai seguenti blocchi di byte:
*   **Radiotap Header (8 byte, opzionale)**: Metadati necessari solo ai driver moderni (es. `mac80211`) per indicare i parametri di trasmissione (come la potenza e l'antenna). Non fa strettamente parte dello standard 802.11.
*   **Frame Control (2 byte)**: Specifica il tipo di pacchetto. Contiene i codici `Type = 0` (Management) e `Subtype = 12` (Deauthentication). È il flag che innesca la disconnessione.
*   **Duration (2 byte)**: Indica il tempo di occupazione del canale (solitamente lasciato a `0x0000`).
*   **Address 1 (6 byte) - Destinazione**: Il MAC Address della vittima da disconnettere (o `FF:FF:FF:FF:FF:FF` per colpire tutti i dispositivi, broadcast).
*   **Address 2 (6 byte) - Sorgente**: Il MAC Address del mittente. L'attaccante inserisce qui il MAC dell'Access Point legittimo (Spoofing) per far credere al client che l'espulsione arrivi dal vero router.
*   **Address 3 (6 byte) - BSSID**: Il MAC Address che identifica la rete Wi-Fi bersaglio (quasi sempre identico alla Sorgente).
*   **Sequence Control (2 byte)**: Un numero progressivo per evitare che i dispositivi scartino il frame considerandolo un duplicato.
*   **Reason Code (2 byte)**: Un codice standard che specifica il motivo dell'espulsione. Spesso si usa il codice `1` (Unspecified) oppure codici legati a inattività/errori per non destare sospetti nel sistema operativo del client.
