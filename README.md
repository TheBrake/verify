# Verify - V 1.0

Herramienta CLI en Rust que actúa como **Git hook local de pre-push**. Se encarga de
interceptar `git push`, lee únicamente el diff que está a punto de salir de
la máquina y bloquea la subida si detecta credenciales, ficheros `.env` o
llaves de API entre otras cosas que desees configurarlo 

Diseñada para ser **rápida, offline y memory-safe**. No escanea el disco,
no llama a APIs externas y no verifica secretos en vivo (eso es trabajo
de CI, no de un hook que debe responder en milisegundos).

## Flujo del Work

```
git push
   │
   ▼
.git/hooks/pre-push   →  exec verify hook-run
   │
   ▼
Git entrega por stdin:
   <local-ref> <local-sha> <remote-ref> <remote-sha>
   │
   ▼
verify pide a Git el unified diff de ese rango (solo líneas +)
   │
   ▼
prefiltro Aho-Corasick  →  regex precisas  →  entropía de Shannon
   │
   ├─ limpio      exit 0  →  el push continúa
   └─ leak        exit 1  →  el push se cancela + alerta en terminal
```

## Instalación

```bash
cargo install --path .
cd a tu repositorio
verify install
verify init       
```

## Uso

```bash
verify scan                     # rango sin pushear, o diff vs HEAD
verify scan src/config.rs       # ficheros sueltos
git diff origin/main..HEAD | verify scan --diff
verify rules                    # catálogo built-in
verify uninstall
```

Códigos de salida: `0` limpio, `1` leak bloqueante, `2` error de runtime.

Bypass de emergencia: `git push --no-verify`.

## Configuración (`verify.toml`)

```toml
[verify]
fail_on = "any"          # any | high
redact = true
entropy_enabled = true
entropy_min_length = 24
entropy_threshold = 4.5
block_env_files = true

[paths]
exclude = ["**/tests/fixtures/**"]

[[rules]]
id = "prod-postgres"
description = "No production PostgreSQL connection strings"
pattern = '(?i)postgres(?:ql)?://[^\s]+:[^\s]+@[^\s]*(?:prod|production)'
severity = "critical"

[[allow]]
rule = "generic-api-key"
path = "testdata/sample.env"
contains = "EXAMPLE_NOT_A_REAL_KEY"
```

También se puede silenciar una línea concreta con `// verify:allow`.

## Qué detecta de serie en la v1

AWS keys, tokens de GitHub/GitLab/Slack/Stripe/OpenAI/Google, JWTs,
PEM private keys, connection strings de Postgres/MySQL/Mongo/Redis,
asignaciones `DATABASE_URL` / `API_KEY` / `password`, ficheros `.env`
nuevos, y tokens de alta entropía desconocidos.

## Por qué este stack

Documentado en la conversación que acompaña al repo: clap, serde+toml,
regex + aho-corasick, Shannon entropy, subprocess de `git` (no libgit2),
binario estático, LTO, cero red.

## Por TheBrakesito (TheBrake)
