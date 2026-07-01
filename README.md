# DeepRecon 🔍

Scanner de vulnerabilidades web completo com 24 passos automatizados.

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
| 22 | Exploração agressiva | XSS, path traversal, .git/.env expostos, CORS, default creds, SSTI, PUT webshell, open redirect |
| 23 | Análise inteligente | Correlaciona achados e dá sugestões |
| 24 | Informações do site | Servidor, Cloudflare, idade do domínio, SSL, IP, ASN |

## Relatório

O relatório completo é salvo em `/tmp/DeepRecon_<dominio>_<data>.txt`.

## Requisitos

- Kali Linux ou Debian-based
- Ferramentas instaladas automaticamente pelo script (via apt)

## Aviso Legal

O uso deste scanner é de **total responsabilidade do usuário**. Utilize apenas em sistemas que você possui ou tem autorização explícita por escrito.
