# Verify V1

CLI en Rust que actúa como **hook local de pre-push**. Intercepta `git push`,
lee solo el diff que está a punto de salir de la máquina y bloquea la subida
si detecta credenciales, ficheros `.env` nuevos o claves de API.

Diseñada para ser **rápida, offline y memory-safe**. No camina el disco,
no llama a APIs externas y no verifica secretos en vivo (eso es trabajo
de CI). El hook tiene que responder en milisegundos.

```
git push
   │
   ▼
pre-push  →  exec verify hook-run <remote> <url>
   │
   ▼
Git entrega por stdin:
   <local-ref> <local-sha> <remote-ref> <remote-sha>
   │
   ▼
verify pide a Git el unified diff de ese rango (solo líneas +)
   │
   ▼
reglas built-in + custom  →  entropy de Shannon (fallback)
   │
   ├─ nada que bloquee     exit 0  →  el push sigue
   ├─ finding que blocks   exit 1  →  el push se cancela
   └─ hook roto / I/O      exit 2  →  el push se cancela
```

`verify install` escribe el hook donde Git lo ejecuta
(`git rev-parse --git-path hooks`), no a ciegas en `.git/hooks`.
Respeta `core.hooksPath` y worktrees.

## Instalación

```bash
cargo install --path . --locked
cd tu-repositorio
verify init                 # escribe verify.toml (no instala el hook)
verify install              # planta pre-push donde Git lo corre
```

`init` y `install` son dos pasos a propósito. Un repo con config y sin hook
sigue desprotegido.

`--force` en `init` pisa `verify.toml` pero deja `verify.toml.bak`.
`--force` en `install` sustituye un hook ajeno; **no lo encadena**
(husky / lefthook hay que componerlos a mano).

## Uso

```bash
verify scan                          # unpushed + working tree
verify scan src/config.rs .env       # ficheros sueltos
git diff origin/main..HEAD | verify scan --diff
git diff origin/main..HEAD | verify  # sin comando: si parece diff, es scan
verify rules                         # catálogo built-in (y si son overridable)
verify uninstall
```

Flags útiles:

```
-c, --config PATH         verify.toml explícito
    --fail-on any|high    pisa el TOML (también VERIFY_FAIL_ON)
    --show-secrets        no redactar snippets
    --diff                stdin = unified diff (incompatible con FILES)
```

Códigos de salida:

| Código | Significado |
|---|---|
| 0 | limpio, o solo findings por debajo de `fail_on`, o push delete-only |
| 1 | hay al menos un finding que `blocks` |
| 2 | error de runtime (config rota, hook sin stdin, diff sin path, I/O) |

Un hook mal instalado que no recibe el protocolo de Git **sale 2**, no 0.
Bypass de emergencia: `git push --no-verify` (auditable; última opción).

## Configuración

Se busca, en este orden:

1. `-c` / `--config`
2. `verify.toml` en la raíz del repo
3. `.verify.toml` en la raíz del repo

```toml
[verify]
fail_on = "any"          # any | high  (high = solo critical/high)
redact = true
max_file_bytes = 1048576
entropy_enabled = true
entropy_min_length = 24
entropy_threshold = 4.5
block_env_files = true

[paths]
replace_excludes = false
exclude = ["**/tests/fixtures/**", "**/*.md"]

[[rules]]
id = "prod-postgres"
description = "No production PostgreSQL connection strings"
pattern = '(?i)postgres(?:ql)?://[^\s]+:[^\s]+@[^\s]*(?:prod|production)'
severity = "critical"
keywords = ["postgres"]
# path = "**/*.env"
# entropy = 3.5
# secret_group = 1

[[allow]]
rule = "generic-api-key"
paths = ["testdata/sample.env"]
contains = "EXAMPLE_NOT_A_REAL_KEY"
condition = "and"
# fingerprint = "vf_…"
```

- Reusar el `id` de una built-in **la sustituye**.
- Claves desconocidas o reglas sin `id`/`pattern` fallan al cargar. No hay
  “config rota y el hook pasa”.
- `fail_on = "high"` deja los Medium (p. ej. `high-entropy`) como
  **reported**: salen en el informe y el hook sigue en 0.

Silencio por línea, solo en un comentario real (`#`, `//`, `/*`, `--`):

```
password = "…"  // verify:allow
token = "…"     // verify:allow:jwt
```

Un valor que *contenga* el texto `verify:allow` no apaga el hook.
También se puede pegar en `verify.toml` el fingerprint que imprime el reporte:

```toml
[[allow]]
fingerprint = "vf_…"
```

## Qué detecta de serie

AWS (`AKIA` / `ASIA` y secret keys), GitHub / GitLab / Slack / Stripe /
OpenAI (incl. `sk-proj-`), Google, JWT, PEM (`BEGIN … PRIVATE KEY`,
también ED25519 y ENCRYPTED), connection strings
Postgres / MySQL / Mongo / Redis, asignaciones `DATABASE_URL` /
`API_KEY` / `password`, ficheros `.env` nuevos, y tokens de alta
entropía desconocidos (fallback: no se emiten si una regla ya pegó
en esa línea).

`verify rules` lista el catálogo y marca cuáles se pueden overridear.

## Límites a propósito

- Solo líneas añadidas del diff (y los ficheros que pases a `scan`).
  No es un historial tipo `git log -p`.
- `max_file_bytes` se aplica al archivo entero, no a la línea.
- Color ANSI solo si stderr es TTY. En CI el fingerprint se copia limpio.
- MSRV **1.75**. Compilar y testear con `cargo test --locked`.

## Por TheBrakesito (TheBrake)
