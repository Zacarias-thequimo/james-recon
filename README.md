<p align="center">
  <pre>
     ██╗ █████╗ ███╗   ███╗███████╗███████╗
     ██║██╔══██╗████╗ ████║██╔════╝██╔════╝
     ██║███████║██╔████╔██║█████╗  ███████╗
██   ██║██╔══██║██║╚██╔╝██║██╔══╝  ╚════██║
╚█████╔╝██║  ██║██║ ╚═╝ ██║███████╗███████║
 ╚════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝
  </pre>
</p>

<h3 align="center">Toolkit de Reconhecimento & Exploração para Pentest</h3>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.2.0-blue" alt="version">
  <img src="https://img.shields.io/badge/python-3.10+-green" alt="python">
  <img src="https://img.shields.io/badge/modules-13-orange" alt="modules">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="license">
</p>

---

**James** é uma ferramenta modular e assíncrona de reconhecimento, análise de segurança e exploração, desenhada para testes de penetração autorizados e competições CTF. Escrita em Python com `asyncio`, `httpx` e `rich`.

## Funcionalidades

- Pipeline assíncrono com 13 módulos executados em sequência
- Enumeração de subdomínios, port scan, fingerprinting, OSINT, CVE lookup
- Análise SSL/TLS, auditoria de security headers, detecção de CORS
- Web crawler com extração de endpoints em JS bundles
- Descoberta automática de formulários com **detecção de SQL Injection** (boolean blind + time-based)
- Sugestão e execução de cadeias de exploração
- Relatórios em JSON e Markdown
- Dois modos: CLI com flags e interativo com menu

---

## Instalação

```bash
git clone https://github.com/Zacarias-thequimo/james-recon.git
cd james-recon
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Dependências

| Pacote | Uso |
|--------|-----|
| `httpx` | Requisições HTTP assíncronas |
| `aiodns` | Resolução DNS assíncrona |
| `click` | Interface CLI |
| `rich` | Output formatado (tabelas, cores, painéis) |
| `python-whois` | Consultas WHOIS |

---

## Uso

### CLI

```bash
# Varredura completa contra um alvo
python main.py scan -t exemplo.com

# Apenas módulos específicos
python main.py scan -t exemplo.com -m subdomain,portscan,ssl_check

# Portas customizadas + relatório JSON
python main.py scan -t exemplo.com -p 1-1000 -o relatorio.json

# Wordlist customizada para fuzzing e subdomínios
python main.py scan -t exemplo.com -w /usr/share/wordlists/dirb/common.txt

# Varredura completa com exploração ativa + relatório markdown
python main.py scan -t exemplo.com --i-have-permission --format md -o report.md

# Verificar versão
python main.py --version
```

#### Opções

| Flag | Descrição | Default |
|------|-----------|---------|
| `-t, --target` | Domínio alvo | (obrigatório) |
| `-m, --modules` | Lista de módulos separados por vírgula | todos |
| `-o, --output` | Caminho do ficheiro de saída | (sem saída) |
| `--format` | Formato: `json` ou `md` | `json` |
| `-p, --ports` | Faixa de portas (`1-1000`, `80,443,8080`) | top ports |
| `--threads` | Nível de concorrência | `50` |
| `-w, --wordlist` | Wordlist customizada para fuzzing/subdomínios | built-in |
| `--i-have-permission` | Habilitar módulos de exploração activa | desligado |

### Modo Interativo

```bash
python main.py
```

Abre um shell interativo com menu:

```
james> alvo exemplo.com         # define o alvo
james> varrer                   # executa pipeline completo
james> rodar subdomain,portscan # executa módulos específicos
james> modulos                  # lista todos os módulos
james> modo-exploit             # liga/desliga exploração activa
james> status                   # mostra resultados da sessão
james> salvar                   # exporta relatório (JSON/MD)
james> limpar                   # limpa sessão
james> ajuda                    # mostra ajuda
james> sair                     # encerra
```

---

## Módulos

James opera através de um pipeline sequencial. Cada módulo recebe o objecto `Target`, enriquece-o com dados e passa ao próximo.

### Reconhecimento (6 módulos)

| Módulo | Descrição | O que faz |
|--------|-----------|-----------|
| `subdomain` | Enumeração de subdomínios | Resolve DNS para cada entrada da wordlist + bruteforce. Popula `target.subdomains` |
| `portscan` | Port scan assíncrono | Varre portas TCP com detecção de banner/serviço. Popula `target.open_ports` |
| `fingerprint` | Fingerprinting web | Analisa headers HTTP, meta tags, cookies, scripts para identificar stack. Popula `target.technologies` |
| `osint` | OSINT passivo | Consulta DNS (A, AAAA, MX, TXT, NS, SOA), WHOIS, e busca emails expostos. Popula `target.dns_records`, `target.whois_data`, `target.emails` |
| `cve_check` | CVE lookup | Busca CVEs conhecidas para as tecnologias/versões detectadas. Popula `target.cves` |
| `fuzzer` | Directory fuzzing | Faz bruteforce de diretórios e ficheiros via wordlist. Popula `target.fuzz_results` |

### Análise de Segurança (4 módulos — v1.2.0)

| Módulo | Descrição | O que faz |
|--------|-----------|-----------|
| `ssl_check` | Análise SSL/TLS | Verifica protocolo, cifra, emissor, SANs, data de expiração para todos os hosts descobertos. Alerta para certs a expirar (<30 dias) e hostname mismatch. Popula `target.ssl_info` |
| `headers_check` | Auditoria de headers | Verifica 7 security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection), detecta info leak headers (Server, X-Powered-By), analisa fraquezas no CSP, testa CORS com `Origin: https://evil.com`. Popula `target.security_headers`, `target.cors_issues` |
| `crawler` | Web spider | Descobre páginas seguindo links (max 50), extrai URLs de ficheiros JS, identifica endpoints `/api/` via regex, prova endpoints descobertos. Popula `target.fuzz_results` (acumula) |
| `form_analyzer` | Análise de formulários + SQLi | Descobre `<form>` em todas as páginas acessíveis, extrai inputs, verifica tokens CSRF. **Testa SQLi automaticamente**: (1) request baseline, (2) injecção de `'`, (3) balanced quotes `''`, (4) detecção de SQL errors, (5) boolean blind (diferencial de tamanho >50%), (6) time-based com `SLEEP(3)`. Popula `target.forms`, `target.sqli_results` |

### Exploração (3 módulos)

| Módulo | Descrição | O que faz |
|--------|-----------|-----------|
| `exploit_chain` | Cadeia de exploits | Analisa todos os dados recolhidos e sugere cadeias de exploração viáveis. Popula `target.exploit_suggestions` |
| `exploit_runner` | Execução de exploits | Executa exploits contra serviços vulneráveis detectados. Requer `--i-have-permission`. Popula `target.exploit_results` |
| `pg_exploit` | PostgreSQL exploit | Testa credenciais padrão, enumeração de bases, tentativa de RCE via `COPY TO PROGRAM`. Requer `--i-have-permission`. Popula `target.exploit_results` |

---

## Arquitectura

```
james-recon/
├── main.py                 # Entry point — CLI (click) + modo interativo (rich)
├── core/
│   ├── module.py           # BaseModule — classe abstracta (name, description, run())
│   ├── target.py           # Target dataclass — modelo central com todos os campos
│   ├── pipeline.py         # Pipeline — motor sequencial de execução dos módulos
│   ├── report.py           # Geração de relatórios JSON e Markdown
│   └── paths.py            # Resolução de caminhos (wordlists, dist)
├── modules/
│   ├── subdomain.py        # SubdomainEnum
│   ├── portscan.py         # PortScan
│   ├── fingerprint.py      # Fingerprint
│   ├── osint.py            # OSINT
│   ├── cve_check.py        # CVECheck
│   ├── fuzzer.py           # Fuzzer
│   ├── ssl_check.py        # SSLCheck
│   ├── headers_check.py    # HeadersCheck
│   ├── crawler.py          # Crawler
│   ├── form_analyzer.py    # FormAnalyzer
│   ├── exploit_chain.py    # ExploitChain
│   ├── exploit_runner.py   # ExploitRunner
│   └── pg_exploit.py       # PgExploit
├── wordlists/
│   ├── subdomains.txt      # ~100 prefixos comuns (www, mail, ftp, dev, ...)
│   └── dirs.txt            # ~200 paths comuns (/admin, /login, /api, ...)
└── requirements.txt
```

### Fluxo de Dados

```
                    ┌──────────────────────────────────────────────┐
                    │                  Target                       │
                    │  domain, ip, subdomains, open_ports,          │
                    │  technologies, dns_records, whois_data,       │
                    │  emails, cves, fuzz_results, ssl_info,        │
                    │  security_headers, cors_issues, forms,        │
                    │  sqli_results, vulns, exploit_suggestions,    │
                    │  exploit_results                              │
                    └──────────────┬───────────────────────────────┘
                                   │
     ┌─────────┬─────────┬─────────┼─────────┬─────────┬──────────┐
     ▼         ▼         ▼         ▼         ▼         ▼          ▼
 subdomain  portscan  finger   osint    cve_check  fuzzer     ...
     │         │         │         │         │         │
     └─────────┴─────────┴─────────┴─────────┴─────────┘
                                   │
     ┌─────────┬─────────┬─────────┤
     ▼         ▼         ▼         ▼
 ssl_check  headers  crawler  form_analyzer
     │         │         │         │
     └─────────┴─────────┴─────────┘
                                   │
     ┌─────────┬───────────────────┤
     ▼         ▼                   ▼
 exploit_chain  exploit_runner  pg_exploit
     │              │               │
     └──────────────┴───────────────┘
                    │
                    ▼
              Relatório (JSON/MD)
```

Cada módulo é uma subclasse de `BaseModule` com um método `async run(target: Target) -> Target`. O pipeline executa-os em sequência, permitindo que módulos posteriores utilizem dados dos anteriores (ex: `form_analyzer` usa páginas encontradas pelo `crawler` e `fuzzer`).

---

## Exemplos de Uso

### Reconhecimento rápido de subdomínios e portas
```bash
python main.py scan -t alvo.com -m subdomain,portscan,fingerprint
```

### Auditoria de segurança web (headers, SSL, forms)
```bash
python main.py scan -t alvo.com -m ssl_check,headers_check,crawler,form_analyzer -o audit.md --format md
```

### Varredura completa com exploração autorizada
```bash
python main.py scan -t alvo.com --i-have-permission -o resultado.md --format md
```

### Scan com portas expandidas e wordlist custom
```bash
python main.py scan -t alvo.com -p 1-10000 --threads 100 -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### Sessão interativa
```bash
$ python main.py

james> alvo empresa.co.mz
james> rodar subdomain,fingerprint,ssl_check
james> status
james> modo-exploit
james> varrer
james> salvar
```

---

## Formato de Saída

### JSON

```json
{
  "domain": "exemplo.com",
  "ip": "1.2.3.4",
  "subdomains": ["www.exemplo.com", "mail.exemplo.com"],
  "open_ports": [{"port": 80, "service": "http", "version": "nginx/1.18.0"}],
  "technologies": {"web_server": "nginx/1.18.0", "cms": "WordPress 6.9.4"},
  "ssl_info": {"exemplo.com": {"protocol": "TLSv1.3", "issuer": "Let's Encrypt"}},
  "security_headers": {"missing": ["HSTS", "CSP", "X-Frame-Options"]},
  "sqli_results": [{"url": "...", "param": "id", "type": "boolean_blind", "severity": "CRITICAL"}],
  "vulns": [{"type": "missing_header", "severity": "MEDIUM", "detail": "..."}]
}
```

### Markdown

Gera relatório estruturado com secções: Informações Gerais, Subdomínios, Portas, Tecnologias, DNS, CVEs, Fuzzing, SSL/TLS, Security Headers, CORS, Formulários, SQL Injection, Vulnerabilidades Consolidadas.

---

## Criar Módulo Customizado

```python
from core.module import BaseModule
from core.target import Target

class MeuModulo(BaseModule):
    name = "meu_modulo"
    description = "Descrição do que faz"

    async def run(self, target: Target) -> Target:
        # Lógica aqui — use httpx, asyncio, etc.
        # Enriqueça target.vulns, target.technologies, etc.
        target.vulns.append({
            "type": "custom_check",
            "severity": "MEDIUM",
            "detail": "Achado encontrado em ...",
        })
        return target
```

Depois registre em `main.py`:

```python
from modules.meu_modulo import MeuModulo

ALL_MODULES_INSTANCES = [
    ...,
    MeuModulo(),
]
```

E adicione ao `build_pipeline()`.

---

## Compilação (binário standalone)

Pode compilar o James num binário único com [PyInstaller](https://pyinstaller.org/), sem precisar de Python instalado na máquina de destino.

```bash
# Instalar PyInstaller
pip install pyinstaller

# Compilar (inclui wordlists e módulos automaticamente)
pyinstaller --onefile \
  --name james \
  --add-data "wordlists:wordlists" \
  --add-data "core:core" \
  --add-data "modules:modules" \
  --hidden-import click \
  --hidden-import rich \
  --hidden-import httpx \
  --hidden-import aiodns \
  --hidden-import whois \
  main.py

# O binário fica em dist/james
./dist/james --version
./dist/james scan -t exemplo.com
```

Ou usar o spec file incluído:

```bash
pyinstaller james.spec
./dist/james --version
```

### Cross-compilation

```bash
# Linux x86_64 (no Linux)
pyinstaller --onefile --name james-linux main.py

# Windows (no Windows ou via Wine)
pyinstaller --onefile --name james.exe main.py
```

O binário gerado (~15-20MB) é portável — basta copiar para a máquina alvo e executar.

---

## Aviso Legal

> **Esta ferramenta destina-se exclusivamente a testes de segurança autorizados, auditorias e competições CTF.**
>
> O uso desta ferramenta contra sistemas sem autorização explícita por escrito é **ilegal** e punível por lei. Os autores não se responsabilizam pelo uso indevido.
>
> Antes de executar com `--i-have-permission`, certifique-se de ter documentação formal de autorização do proprietário do sistema.

## Licença

MIT

## Autor

**Gelson Matavela** ([@Zacarias-thequimo](https://github.com/Zacarias-thequimo))
