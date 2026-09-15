# Verify

Hook local de Git que bloquea secretos **antes** de que existan como commit
o salgan de tu máquina.

No camina el disco. No llama a internet. No es un antivirus ni un CI.
Git lo ejecuta en `pre-commit` y `pre-push`; Verify mira solo las líneas
añadidas (`+`) y decide si el commit o el push siguen.

Sirve en cualquier repo (Python, PHP, Go, Rust, no importa).
Para *usar* Verify hace falta el binario y Git. Cargo y Rust solo hacen
falta si compilas el proyecto tú.

El producto se llama **Verify**. El comando es `verify`.

---

## Qué espera de ti

1. El binario `verify` en tu `PATH`.
2. Un repositorio Git.
3. `verify install` dentro de ese repo.

A partir de ahí, un `git commit` o `git push` normal pasa por Verify.
No tienes que acordarte de escanear a mano.

---

## Cómo funciona

```
git commit
    →  hook pre-commit
    →  verify commit-run
    →  git diff --cached   (solo líneas + del índice)
    →  exit 0  el commit se crea
       exit 1  el commit no existe (hay un secreto)
       exit 2  Verify falló (config, Git, disco)

git push
    →  hook pre-push
    →  verify hook-run
    →  Git manda por stdin las refs que salen
    →  Verify pide el diff de ese rango (solo líneas +)
    →  exit 0  el push sigue
       exit 1  el push se cancela
       exit 2  Verify falló
```

`install` planta los scripts donde Git los corre de verdad
(`git rev-parse --git-path hooks`). Respeta `core.hooksPath` y worktrees.
No escribe a ciegas en `.git/hooks`.

Cada script es corto: `exec <ruta-de-verify> commit-run` o `hook-run`.
Si actualizas el binario, vuelve a correr `verify install --force`.

---

## Instalar en un repo

```bash
verify -v                   # verify 0.1.0 (https://github.com/TheBrake/verify)
cd /ruta/al/repo
verify init                 # escribe verify.toml; no activa hooks
verify install              # planta pre-commit + pre-push
```

`init` e `install` son dos pasos. Config sin hook no protege.

`install` imprime las dos rutas y el comando de cada una:

```
ok installed pre-commit
  path     …/hooks/pre-commit
  runs     '…/verify' commit-run "$@"
  when     git commit  →  scans the index (new and modified files)
ok installed pre-push
  path     …/hooks/pre-push
  runs     '…/verify' hook-run "$@"
  when     git push    →  scans the outgoing range
```

Comprobar:

```bash
ls "$(git rev-parse --git-path hooks)/pre-commit"
ls "$(git rev-parse --git-path hooks)/pre-push"
grep "Managed by Verify" "$(git rev-parse --git-path hooks)/pre-commit"
```

`--force` en `init` pisa `verify.toml` y deja `verify.toml.bak`.
`--force` en `install` sustituye un hook que no sea de Verify.
No encadena husky ni lefthook.

Quitar solo lo que Verify escribió:

```bash
verify uninstall
```

### Como tenerlo sin Rust (binario del Release)

```bash
curl -sSL -o verify \
  "https://github.com/TheBrake/verify/releases/download/TAG/verify-x86_64-unknown-linux-musl"
install -m 755 verify ~/.local/bin/verify
cd /ruta/al/repo
verify install
```
Comprueba el checksum publicado junto al binario (`verify-x86_64-unknown-linux-musl.sha256`).
Apple Silicon: `verify-aarch64-apple-darwin`. Windows no entra en V1.


### Compilar el binario

```bash
git clone https://github.com/TheBrake/verify.git
cd verify
cargo install --path . --locked
verify -v
```

Eso deja `verify` en `PATH`. No instala hooks. Los hooks salen de
`verify install` dentro del repo que quieres proteger.

Después de un `git pull` en este repo:

```bash
cd ~/verify
verify update
```

`update` corre `cargo install --path . --locked --force` y vuelve a
plantar los hooks contra el binario nuevo. No hace `git pull` solo.
Si lo corres en un repo que no es este source, solo reescribe hooks
al `verify` que ya está en `PATH`.

MSRV 1.75. Tests: `cargo test --locked`.

---

## Probar que el candado existe

```bash
echo 'PASSWORD=rotated-secret-99' >> .env
git add .env
git commit -m x
```

Tiene que salir **1** y no crear commit. El informe habla de `env-file`
o *commit blocked*. Un commit limpio sale 0.

Atajo de emergencia (deja rastro; última opción):

```bash
git commit --no-verify
git push --no-verify
```

Si te saltas el pre-commit, el pre-push sigue mirando lo que sale.
`--no-verify` no se puede “apagar” desde Verify: es de Git.

**Lo que ya está en un remote no lo borra este hook.** Si una clave
llegó a GitHub, rótala.

---

## Códigos de salida

| Código | Significado |
|---|---|
| 0 | limpio, o solo avisos por debajo de `fail_on`, o push que solo borra ramas |
| 1 | hay al menos un hallazgo que bloquea |
| 2 | error de Verify (config rota, hook sin stdin, I/O) |

Un pre-push mal instalado que no recibe el protocolo de Git sale **2**, no 0.
Scripts y CI deben tratar 1 y 2 como fallo.

---

## Comandos

```bash
verify init
verify install
verify update               # rebuild + replant (from the Verify clone)
verify uninstall
verify scan                          # unpushed + working tree
verify scan src/config.rs .env
git diff origin/main..HEAD | verify scan --diff
git diff origin/main..HEAD | verify  # si stdin parece diff, es scan
verify rules
verify -v
verify --help
```

Flags:

```
-c, --config PATH         verify.toml explícito
    --fail-on any|high    pisa el TOML (también VERIFY_FAIL_ON)
    --show-secrets        no redactar el valor encontrado
    --diff                stdin = unified diff (no se mezcla con FILES)
    --force               pisa archivos en init / install
```

---

## Qué detecta

Reglas incluidas, sin red:

- AWS (`AKIA` / `ASIA` y secret keys)
- GitHub, GitLab, Slack, Stripe, OpenAI (incl. `sk-proj-`), Google
- JWT y PEM (`BEGIN … PRIVATE KEY`, también ED25519 y ENCRYPTED)
- Connection strings Postgres / MySQL / Mongo / Redis
- Asignaciones `DATABASE_URL` / `API_KEY` / `password`
- Ficheros `.env` / `.env.*` **nuevos o modificados**
  (no `.env.example`, `.sample`, `.template`, `.test`)
- Tokens de alta entropía desconocidos (solo si ninguna regla pegó ya
  en esa línea)

El pre-commit mira el índice. Si alguien borra `.gitignore` y hace
`git add .`, el `.env` entra al stage y Verify lo corta antes de crear
el commit.

---

## Configuración

Orden de búsqueda:

1. `-c` / `--config`
2. `verify.toml` en la raíz del repo
3. `.verify.toml` en la raíz del repo

```toml
[verify]
fail_on = "any"          # any = todo; high = solo critical/high
redact = true
max_file_bytes = 1048576
entropy_enabled = true
entropy_min_length = 24
entropy_threshold = 4.5
block_env_files = true

[paths]
replace_excludes = false
exclude = ["**/tests/fixtures/**", "**/*.md"]
```

Una regla tuya con el mismo `id` que una incluida **la sustituye**.
Claves desconocidas o reglas sin `id`/`pattern` fallan al cargar:
el hook no pasa “porque la config está rota”.

`fail_on = "high"` deja los Medium (p. ej. `high-entropy`) como aviso:
salen en el informe y el hook sigue en 0.

Silencio por línea, solo en un comentario real (`#`, `//`, `/*`, `--`):

```
password = "…"  // verify:allow
token = "…"     // verify:allow:jwt
```

Si el texto `verify:allow` va *dentro* del valor, no cuenta.
También puedes pegar el fingerprint que imprime el informe:

```toml
[[allow]]
fingerprint = "vf_…"
```

Plantilla completa: `verify.toml.example` en este repo, o `verify init`.

---

## Límites

- Solo líneas añadidas del diff (y los ficheros que pases a `scan`).
  No recorre historia (`git log -p`) ni untracked sin stage.
- `max_file_bytes` vale para el archivo entero, no para una línea.
- Color ANSI solo si stderr es una terminal.
- No rota credenciales. No limpia un remote. No sustituye un scanner de CI.

---

Por (TheBrake)
