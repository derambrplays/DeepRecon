# DeepRecon 🔍

Scanner de vulnerabilidades web completo com **35 passos automatizados**, score heurístico de risco (Joguin IA), análise SSL (A-F), relatórios TXT/HTML/JSON, integração Metasploit e detecção adaptativa de hardware/rede.

## Instalação

```bash
git clone https://github.com/derambrplays/DeepRecon.git
cd DeepRecon
chmod +x deeprecon.sh
```

## Uso

```bash
./deeprecon.sh
```

O menu interativo oferece 3 modos:
- `[1]` Alvo único
- `[2]` Múltiplos alvos
- `[3]` Arquivo de alvos

### Argumento direto

```bash
./deeprecon.sh https://alvo.com
```

Pula o menu interativo e inicia o scan imediatamente.

## Passos

| # | Etapa | Descrição |
|---|-------|-----------|
| 1 | WAFW00F | Detecta Web Application Firewall |
| 2 | Headers | Analisa headers de segurança (HSTS, CSP, X-Frame-Options) |
| 3 | WhatWeb | Identifica tecnologias do site |
| 4 | SSLScan | Verifica SSL/TLS, Heartbleed, validade do certificado |
| 5 | Subfinder + Amass | Descobre subdomínios |
| 6 | Nmap | Escaneia portas abertas e serviços |
| 7 | Gobuster | Força bruta de diretórios |
| 8 | Arquivos sensíveis | Procura admin, backup, .git, .env, phpinfo |
| 9 | SQLMap | Testa SQL Injection (GET, forms, cookies) |
| 10 | Commix | Testa Command Injection |
| 11 | FFUF | Força bruta adicional de diretórios |
| 12 | WFuzz | Fuzzing de parâmetros |
| 13 | Nikto | Varredura geral de vulnerabilidades |
| 14 | WPScan | Verifica WordPress |
| 15 | Hydra | Testa senhas padrão |
| 16 | DNSRecon | Informações de DNS |
| 17 | Whois | Informações do domínio |
| 18 | SearchSploit | Busca exploits conhecidos |
| 19 | Métodos HTTP | Verifica OPTIONS, PUT |
| 20 | Serviços comuns | Procura phpMyAdmin, cgi-bin, etc |
| 21 | CVE Check | Verifica versões antigas de servidores |
| 22 | Exploração agressiva | XSS, path traversal, .git/.env, CORS, default creds, SSTI, PUT webshell, open redirect |
| 23 | Metasploit | 7 scanners auxiliares (http_header, robots_txt, git_scanner, etc) |
| 24 | Joguin IA | Score heurístico: narrativa, score, CVSS, quick wins, roadmap, superfície de ataque |
| 25 | Info do site | Servidor, CDN, SSL, whois, idade do domínio, tecnologias |
| 26 | Email Security | SPF, DMARC, DKIM, BIMI, MX records |
| 27 | Robots/Security/Sitemap | Análise de robots.txt, security.txt, sitemap.xml |
| 28 | SSL Grade (A-F) | Classificação SSL Labs style com pontos por TLS, HSTS, PFS, ciphers |
| 29 | JWT Hunter | Busca tokens JWT em cookies, headers, HTML; analisa flags de segurança |
| 30 | Traceroute | Mapeamento de rota de rede com hops e latência |
| 31 | WAF Behavior | Teste de rate limiting e detecção de WAF com payloads maliciosos |
| 32 | Tech CVE Lookup | Correlaciona versões de tecnologias com CVEs e searchsploit |
| 33 | JSON Export | Gera relatório estruturado em JSON |
| 34 | HTML Report | Relatório visual profissional com CSS e barra de risco |
| 35 | Deep Ports | Escaneia portas incomuns (CPanel, Webmin, backdoors) |

## Relatórios

Três formatos gerados automaticamente:

- **TXT**: `/tmp/DeepRecon_<dominio>_<data>.txt` — relatório completo em texto
- **HTML**: `/tmp/DeepRecon_<dominio>_<data>.html` — relatório visual com CSS profissional
- **JSON**: `/tmp/DeepRecon_<dominio>_<data>.json` — relatório estruturado para integração

### Visualizar relatórios

```bash
cat /tmp/DeepRecon_*.txt          # TXT
firefox /tmp/DeepRecon_*.html     # HTML
cat /tmp/DeepRecon_*.json | jq .  # JSON (requer jq)
```

## Funcionalidades

- **35 passos automatizados** de reconhecimento e exploração
- **Joguin IA**: score heurístico de risco com CVSS 3.1, cadeias de ataque, quick wins, roadmap de remediação (não é LLM — sem alucinações)
- **Metasploit**: 7 scanners auxiliares integrados
- **SSL Grade**: classificação A+ a F estilo SSL Labs
- **Email Security**: SPF, DMARC, DKIM, BIMI
- **JWT Hunter**: detecção de tokens expostos em cookies/headers/HTML
- **HTML Report**: relatório visual profissional com CSS dark mode
- **JSON Export**: saída estruturada para ferramentas externas
- **Hardware Detection**: ajusta threads automaticamente (5/15/30) baseado em CPU/RAM
- **Loading Bar**: barra de progresso visual com percentual
- **Full scan**: 25 portas comuns + portas incomuns (35 adicionais)
- **Argumento CLI**: `./deeprecon.sh <url>` para execução direta

## Problemas Resolvidos

### 0. "Joguin IA" substitui "IA Brain"
- O antigo "IA Brain" foi renomeado para **Joguin IA** para deixar claro que é um **score heurístico matemático** (pesos + contagens), **não um LLM**.
- Sem alucinações: o score reflete exatamente os achados do scan, sem inventar riscos.

### 1. Rate Limiting Global (evita DoS, EDoS e travamento da rede)
- Delay entre requisições configurável por modo (Furtivo=1000ms, Medio=300ms, Bruto=100ms)
- Threads das ferramentas (Gobuster, FFUF) limitadas pelo rate limit
- Nmap com `--min-rate` reduzido (50/200/500) em vez de 1000 fixo
- Modo Furtivo usa delay de 1s entre requisições — seguro para qualquer roteador
- `curl_rapido` com controle de taxa embutido

### 2. Modo Furtivo sem brute force web
- Em modo Furtivo, Gobuster, FFUF e WFuzz são **pulados automaticamente** — o delay de 1s entre requisições tornaria a varredura de wordlists (50k+ palavras) inviável (~14h).
- O modo Furtivo foca apenas em reconhecimento passivo e testes leves.

### 3. Correlação de Portas (serviço detectado por nome, não só por porta fixa)
- Nmap extrai nome do serviço (`http`, `www`, `proxy`, `api`, `graphql`, `rest`, `dashboard`) via `-sV`
- Portas web comuns ampliadas: 80, 443, 8080, 8443, **3000, 5000, 8000, 8888, 9000, 9090, 9443**
- Servidor web na porta 5000 ou 9000 → `WEB_ATIVO=1` ativado pelo nome do serviço ou pela porta
- Gobuster, SQLMap, Commix, FFUF, WFuzz, Nikto, WPScan, Hydra, Metasploit e demais testes HTTP só executam com `WEB_ATIVO=1`
- Evita centenas de erros e minutos perdidos contra portas fechadas

### 4. Verificação de Versões de Ferramentas
- `verificar_versoes()` agora checa: Python 3, Go, Nmap (≥ 7.x), Ruby
- Avisa se alguma ferramenta crítica estiver ausente ou desatualizada antes de começar o scan

### 5. Threads Ajustadas pela Rede (não só CPU/RAM)
- Teste de latência contra 8.8.8.8 no startup
- Rede lenta (>200ms): fator 0.3 — threads reduzidas para não saturar o Wi-Fi
- Rede média (>80ms): fator 0.6
- Rede rápida (<80ms): fator 1.0
- Impede notebook potente em Wi-Fi de hotel de queimar a conexão com 30 threads

### 6. SQLMap com timeout — não trava o script
- Cada chamada do SQLMap (GET, forms, cookie) tem **timeout de 120s**
- Commix com timeout de 90s
- Script continua linear por arquitetura shell, mas timeouts evitam bloqueio permanente

### 7. WPScan só roda com WhatWeb confirmado
- `WHATWEB_OUT` precisa ter conteúdo (WhatWeb executou com sucesso)
- Se WhatWeb não rodou (ferramenta ausente ou falha), WPScan é pulado com aviso explícito

### 8. Detecção de Nuvem + Alerta EDoS
- Identifica Cloudflare, AWS CloudFront, Google Cloud, Akamai, Incapsula via headers
- Alerta sobre risco de cobrança financeira por auto-scaling (Economic Denial of Sustainability)
- Em modo Bruto, pergunta se deseja continuar antes de prosseguir

### 9. Suporte a .env para API Keys
- Carrega automaticamente `$SCRIPT_DIR/.env` ou `~/.config/deeprecon/.env`
- WPScan usa `WPSCAN_API_TOKEN` do `.env` no `--api-token`
- `.env.example` incluso com documentação das chaves suportadas
- `.env` e `reports/` no `.gitignore` — sem risco de vazar chaves no repositório

### 10. Correções Gerais
- Bug de sintaxe corrigido: heredoc duplo substituído por template com placeholders + `sed`
- Nmap `else` ausente: "Nmap não disponível" agora só aparece quando nmap realmente não está instalado
- `bash -n` limpo em todas as versões

## Requisitos

- Kali Linux ou Debian-based
- Conexão com internet
- ~2GB de RAM recomendado (mínimo 512MB com modo BAIXO)
- Ferramentas instaladas automaticamente pelo script (via apt)

## Aviso Legal

O uso deste scanner é de **total responsabilidade do usuário**. Utilize apenas em sistemas que você possui ou tem autorização explícita por escrito.
