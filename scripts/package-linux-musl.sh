
set -eu

target="${VERIFY_DIST_TARGET:-x86_64-unknown-linux-musl}"
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

cargo build --locked --release --target "$target"

src="target/${target}/release/verify"
if [ ! -f "$src" ]; then
  echo "package-linux-musl: missing $src" >&2
  exit 1
fi

mkdir -p dist
dest="dist/verify-${target}"
cp "$src" "$dest"
chmod 755 "$dest"

if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum "verify-${target}" > "verify-${target}.sha256")
else
  (cd dist && shasum -a 256 "verify-${target}" > "verify-${target}.sha256")
fi

echo "ok  $dest"
cat "dist/verify-${target}.sha256"