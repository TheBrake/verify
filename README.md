# Verify

Hook local de Git que bloquea secretos **antes** de que existan como commit
o salgan de tu máquina.

No camina el disco. No llama a internet. No es un antivirus ni un CI.
Git lo ejecuta en `pre-commit` y `pre-push`. Verify mira solo las líneas
añadidas (`+`) y decide si el commit o el push siguen.

Sirve en cualquier repo: Python, PHP, Go, Rust, da igual.
Para *usar* Verify hacen falta el binario y Git. No hace falta saber Rust.

El producto se llama **Verify** y el comando es... `verify`.

---

## Tener el binario

```bash
base=https://github.com/TheBrake/verify/releases/latest/download

curl -sSL -o verify-x86_64-unknown-linux-musl \
  "$base/verify-x86_64-unknown-linux-musl"

curl -sSL -o verify-x86_64-unknown-linux-musl.sha256 \
  "$base/verify-x86_64-unknown-linux-musl.sha256"

sha256sum -c verify-x86_64-unknown-linux-musl.sha256

install -m 755 verify-x86_64-unknown-linux-musl ~/.local/bin/verify

verify -v
```

El checksum lista el nombre largo del artefacto; no renombres el fichero
hasta *después* de `sha256sum -c`.

Apple Silicon: el mismo flujo con `verify-aarch64-apple-darwin` y
`shasum -a 256 -c`. Windows no entra en V1 (los hooks son scripts Unix).

---

## Instalarlo en un repo

En el repositorio que quieres proteger (el de tu app, no este):

```bash
cd /ruta/al/repo
verify init                 # escribe verify.toml; no activa hooks
verify install              # planta pre-commit + pre-push
```

`init` e `install` son dos pasos. Config sin hook no protege.

`install` imprime las dos rutas y qué corre cada una:

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

Los scripts van donde Git los ejecuta de verdad
(`git rev-parse --git-path hooks`). Respeta `core.hooksPath` y worktrees.
No escribe a ciegas en `.git/hooks`.

```bash
ls "$(git rev-parse --git-path hooks)/pre-commit"
ls "$(git rev-parse --git-path hooks)/pre-push"
grep "Managed by Verify" "$(git rev-parse --git-path hooks)/pre-commit"
```

`--force` en `init` pisa `verify.toml` y deja `verify.toml.bak`.
`--force` en `install` sustituye un hook que no sea de Verify.
No encadena husky ni lefthook.

```bash
verify uninstall            # solo quita lo que Verify escribió
```

Si actualizas el binario, vuelve a correr `verify install` (o
`verify update` en ese repo: replanta hooks, no recompila).

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

El pre-commit mira el índice. Si alguien borra `.gitignore` y hace
`git add .`, el `.env` entra al stage y Verify lo corta antes de crear
el commit. Un `.env` *ya tracked* que se modifica también se corta.

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
verify update               # en el repo protegido: solo replanta hooks
verify uninstall
verify scan                          # unpushed + working tree
verify scan app.py .env
git diff origin/main..HEAD | verify scan --diff
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
- `--no-verify` es de Git. El pre-push es la segunda red, no un candado
  de servidor.

---

## [Para los Rustaceans]

Esto es un `[[bin]]`. Git ejecuta un exe, no una crate.

MSRV **1.75**. El lockfile manda.

```bash
git clone https://github.com/TheBrake/verify.git
cd verify
cargo install --path . --locked
verify -v
```

Eso deja `verify` en `PATH`. No instala hooks. Los hooks salen de
`verify install` **dentro del repo que proteges**.

Después de un `git pull` en *este* clone:

```bash
cd /ruta/al/clone/verify
verify update
```

`update` aquí corre `cargo install --path . --locked --force` y replanta
hooks si el cwd es un repo Git. No hace `git pull`. En cualquier otro
directorio solo reescribe los scripts contra el binario que ya está
en `PATH`.

Tests (unitarios + freeze + contrato + portable + integración Git):

```bash
cargo test --locked
```

Artefacto Linux estático, en una máquina de develop:

```bash
sudo apt-get install -y musl-tools
rustup target add x86_64-unknown-linux-musl
sh scripts/package-linux-musl.sh
file dist/verify-x86_64-unknown-linux-musl
```

CI (`.github/ci.yml`): `cargo test --locked` en cada PR; tag `v*` arma
`verify-x86_64-unknown-linux-musl` + `verify-aarch64-apple-darwin` y
deja un draft de GitHub Release. Ese Release *es* el canal de V1.
Homebrew, Scoop, PyPI y `cargo publish` de una lib no entran.

El crate se llama `sverify` para no chocar nombres; el binario se llama
`verify`.

---

Por (TheBrake)
