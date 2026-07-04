# DeepRecon 🔍

Scanner de vulnerabilidades web completo com **42 passos automatizados**, score heurístico de risco (Joguin IA), análise SSL (A-F), relatórios TXT/HTML/JSON, integração Metasploit, menu de ataque pos-scan e detecção adaptativa de hardware/rede.

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
| 3 | WhatWeb | Identifica tecnologias do site (SPA, API, CMS) |
| 4 | SSLScan | Verifica SSL/TLS, Heartbleed, validade do certificado |
| 5 | Subfinder + Amass | Descobre subdomínios |
| 6 | Gau + Wayback | Endpoints históricos (Wayback Machine, AlienVault) |
| 7 | Katana | Crawler moderno de endpoints JS/SPA/API |
| 8 | Nmap | Escaneia portas abertas e serviços |
| 9 | Gobuster | Força bruta de diretórios |
| 10 | Arquivos sensíveis | Procura admin, backup, .git, .env, phpinfo |
| 11 | SQLMap | Testa SQL Injection (GET, forms, cookies) |
| 12 | Commix | Testa Command Injection |
| 13 | FFUF | Força bruta adicional de diretórios |
| 14 | WFuzz | Fuzzing de parâmetros |
| 15 | Nikto | Varredura geral de vulnerabilidades |
| 16 | WPScan | Verifica WordPress |
| 17 | Nuclei | Busca CVEs com templates atualizados |
| 18 | HTTPX | Validação de status + tech detect |
| 19 | Hydra | Testa senhas padrão |
| 20 | DNSRecon | Informações de DNS |
| 21 | Subdomain Takeover | Verifica CNAMEs para serviços cloud abandonados |
| 22 | Whois | Informações do domínio |
| 23 | SearchSploit | Busca exploits conhecidos |
| 24 | Métodos HTTP | Verifica OPTIONS, PUT |
| 25 | Serviços comuns | Procura phpMyAdmin, cgi-bin, etc |
| 26 | CVE Check | Verifica versões antigas de servidores |
| 27 | Exploração agressiva | XSS, path traversal, .git/.env, CORS, default creds, SSTI, PUT webshell, open redirect |
| 28 | Dalfox | XSS automation (centenas de vetores) |
| 29 | Cloud Storage | Testa S3, Azure Blob, Firebase, DigitalOcean Spaces |
| 30 | Race Condition | Requests simultâneos em endpoints críticos |
| 31 | GraphQL Introspection | Query __schema em endpoints GraphQL |
| 32 | HTTP Smuggling | CL.TE request smuggling |
| 33 | JS Secrets | Baixa JS, regexa por chaves API, tokens, senhas |
| 34 | GoWitness | Screenshot visual do alvo |
| 35 | CRLF Injection | Quebra de resposta HTTP com %0d%0a |
| 36 | SSRF | Testa metadata cloud e localhost interno |
| 37 | WebSocket Discovery | Varre endpoints WS/WSS comuns |
| 38 | Metasploit | 7 scanners auxiliares (http_header, robots_txt, git_scanner, etc) |
| 39 | Joguin IA | Score heurístico: narrativa, score, CVSS, quick wins, roadmap, superfície de ataque |
| 40 | SSL Grade (A-F) | Classificação SSL Labs style com pontos por TLS, HSTS, PFS, ciphers |
| 41 | JSON Export | Gera relatório estruturado em JSON |
| 42 | HTML Report | Relatório visual profissional com CSS e barra de risco |

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

- **42 passos automatizados** de reconhecimento e exploração
- **Menu de ataque pos-scan**: 10 ferramentas de invasão (Metasploit, SQLMap, Medusa, Ncrack, Ettercap, DDoS, Nmap custom, Bettercap, Hydra, hping3)
- **Trap de segurança**: Ctrl+C só mata a ferramenta atual, não o script inteiro
- **Safe run**: monitoramento de processo com timeout, detecção de idle e cancelamento controlado
- **Gau + Wayback**: endpoints históricos de Archive.org, AlienVault
- **Katana**: crawler moderno de SPA routes e endpoints dinâmicos
- **Dalfox**: XSS automation com centenas de vetores
- **Subdomain takeover**: verifica CNAMEs contra 17 serviços cloud (AWS, Azure, GitHub, Heroku)
- **Cloud storage discovery**: S3, Azure Blob, Firebase, DigitalOcean Spaces
- **GraphQL introspection**: descobre schema completo se exposto
- **HTTP request smuggling**: CL.TE em portas 80/443/8080/8443
- **JS secrets scanning**: regexa chaves API, tokens, senhas em scripts JS
- **GoWitness**: screenshot visual do alvo
- **CRLF injection**: teste de quebra de resposta HTTP
- **SSRF**: teste de acesso a metadata cloud e localhost
- **WebSocket discovery**: varre endpoints WS/WSS comuns
- **Nuclei**: templates CVE atualizados pela comunidade
- **Race condition**: requests simultâneos em endpoints críticos
- **Joguin IA**: score heurístico de risco com CVSS 3.1, cadeias de ataque, quick wins, roadmap de remediação (não é LLM — sem alucinações)
- **Metasploit**: 7 scanners auxiliares integrados
- **SSL Grade**: classificação A+ a F estilo SSL Labs
- **Email Security**: SPF, DMARC, DKIM, BIMI
- **JWT Hunter**: detecção de tokens expostos em cookies/headers/HTML
- **HTML Report**: relatório visual profissional com CSS dark mode
- **JSON Export**: saída estruturada para ferramentas externas
- **Relatório pós-ataque**: exibe resultados completos após o menu de ataque
- **Verificação de atualizações**: tela com spinner animado + auto-update
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
