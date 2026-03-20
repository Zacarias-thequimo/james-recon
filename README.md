# James v1.2.0 — Toolkit de Reconhecimento & Exploração

Ferramenta modular e assíncrona de reconhecimento, análise de segurança e exploração para pentest e CTF. Escrita em Python.

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso — CLI

```bash
# Varredura completa
python main.py scan -t exemplo.com

# Módulos específicos
python main.py scan -t exemplo.com -m subdomain,portscan,ssl_check

# Portas customizadas + saída em JSON
python main.py scan -t exemplo.com -p 1-1000 -o relatorio.json

# Wordlist customizada
python main.py scan -t exemplo.com -w /usr/share/wordlists/dirb/common.txt

# Modo exploit (requer autorização!)
python main.py scan -t exemplo.com --i-have-permission --format md -o report.md

# Versão
python main.py --version
```

### Opções do `scan`

| Flag | Descrição |
|------|-----------|
| `-t, --target` | Domínio alvo (obrigatório) |
| `-m, --modules` | Módulos separados por vírgula |
| `-o, --output` | Caminho do arquivo de saída |
| `--format` | Formato: `json` ou `md` |
| `-p, --ports` | Faixa de portas (ex: `1-1000` ou `80,443`) |
| `--threads` | Nível de concorrência (padrão: 50) |
| `-w, --wordlist` | Caminho para wordlist customizada |
| `--i-have-permission` | Habilitar exploração ativa |

## Uso — Modo Interativo

```bash
python main.py
```

Comandos disponíveis:

| Comando | Descrição |
|---------|-----------|
| `alvo <domínio>` | Definir o domínio alvo |
| `varrer` | Executar pipeline completo |
| `rodar <mod1,mod2>` | Executar módulos específicos |
| `modulos` | Listar módulos disponíveis |
| `modo-exploit` | Alternar modo exploit |
| `status` | Mostrar resultados atuais |
| `salvar` | Salvar relatório |
| `limpar` | Limpar sessão |
| `ajuda` | Mostrar ajuda |
| `sair` | Encerrar |

## Módulos (13)

### Reconhecimento

| Módulo | Descrição |
|--------|-----------|
| `subdomain` | Enumeração de subdomínios via wordlist e DNS |
| `portscan` | Varredura assíncrona de portas TCP com detecção de serviço |
| `fingerprint` | Fingerprinting de tecnologias web (headers, HTML, cookies) |
| `osint` | Coleta OSINT: DNS, WHOIS e e-mails expostos |
| `cve_check` | Busca de CVEs conhecidas com base nas tecnologias detectadas |
| `fuzzer` | Fuzzing de diretórios e arquivos via wordlist |

### Análise de Segurança (v1.2.0)

| Módulo | Descrição |
|--------|-----------|
| `ssl_check` | Análise de certificados SSL/TLS, protocolo, cifra, expiração |
| `headers_check` | Auditoria de 7 security headers, info leak, CORS |
| `crawler` | Spider de páginas, extração de JS, descoberta de endpoints API |
| `form_analyzer` | Descoberta de formulários, CSRF, **detecção automática de SQLi** |

### Exploração

| Módulo | Descrição |
|--------|-----------|
| `exploit_chain` | Análise e sugestão de cadeias de exploração |
| `exploit_runner` | Execução automatizada de exploits contra serviços vulneráveis |
| `pg_exploit` | Testes de exploração em PostgreSQL (credenciais, RCE) |

## Wordlists

O James inclui wordlists padrão em `wordlists/`. Para usar uma customizada:

```bash
python main.py scan -t exemplo.com -w /caminho/para/wordlist.txt
```

## Exemplos

```bash
# Reconhecimento rápido
python main.py scan -t alvo.com -m subdomain,portscan,fingerprint

# Análise de segurança web
python main.py scan -t alvo.com -m ssl_check,headers_check,crawler,form_analyzer

# Varredura completa com relatório markdown
python main.py scan -t alvo.com --i-have-permission -o resultado.md --format md
```

## Estrutura

```
├── main.py              # Entry point (CLI + interativo)
├── core/
│   ├── target.py        # Modelo de dados do alvo
│   ├── pipeline.py      # Motor de execução dos módulos
│   ├── report.py        # Geração de relatórios (JSON/MD)
│   ├── module.py        # Classe base dos módulos
│   └── paths.py         # Resolução de caminhos
├── modules/
│   ├── subdomain.py     # Enumeração de subdomínios
│   ├── portscan.py      # Port scan assíncrono
│   ├── fingerprint.py   # Fingerprinting web
│   ├── osint.py         # OSINT (DNS, WHOIS, emails)
│   ├── cve_check.py     # Busca de CVEs
│   ├── fuzzer.py        # Directory/file fuzzing
│   ├── ssl_check.py     # Análise SSL/TLS
│   ├── headers_check.py # Auditoria de headers
│   ├── crawler.py       # Web spider
│   ├── form_analyzer.py # Formulários + SQLi auto
│   ├── exploit_chain.py # Cadeia de exploits
│   ├── exploit_runner.py# Execução de exploits
│   └── pg_exploit.py    # PostgreSQL exploit
├── wordlists/
│   ├── subdomains.txt
│   └── dirs.txt
├── relatorios/          # Relatórios gerados
└── requirements.txt
```

## Aviso Legal

**Use esta ferramenta apenas em sistemas que você tem autorização explícita para testar.** O uso não autorizado é ilegal e punível por lei. Os autores não se responsabilizam pelo uso indevido.

## Licença

MIT
