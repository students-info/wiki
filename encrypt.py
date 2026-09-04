import os
import sys
import json
import hashlib
import secrets
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Required package not installed. Run:")
    print("  pip install cryptography")
    sys.exit(1)

PBKDF2_ITERATIONS = 600_000
SALT_LEN = 16
NONCE_LEN = 12

MIME_MAP = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "text/javascript",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ttf": "font/ttf",
    ".mp4": "video/mp4",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
}


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plain: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plain, None)
    return salt + nonce + ct


def decrypt_bytes(buf: bytes, password: str) -> bytes:
    salt = buf[:SALT_LEN]
    nonce = buf[SALT_LEN : SALT_LEN + NONCE_LEN]
    ct = buf[SALT_LEN + NONCE_LEN :]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def get_mime(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    return MIME_MAP.get(ext, "application/octet-stream")


def walk_dir(directory: str) -> list[str]:
    results = []
    for root, _dirs, files in os.walk(directory):
        for f in files:
            results.append(os.path.join(root, f))
    return results


def build_tree(files, files_map, root="content", base=""):
    """Build a nested directory tree from a list of relative file paths.

    files_map: dict mapping relative path (with /) -> encrypted metadata.
    Returns a list of tree nodes; dirs are {'name','type':'dir','children':[]},
    files are {'name','type':'file', ...metadata}.
    """
    tree = []

    def ensure_dir(path_parts, tree_nodes):
        for part in path_parts:
            found = next((n for n in tree_nodes if n["type"] == "dir" and n["name"] == part), None)
            if found is None:
                found = {"name": part, "type": "dir", "children": []}
                tree_nodes.append(found)
            tree_nodes = found["children"]
        return tree_nodes

    for rel in sorted(files):
        parts = rel.split("/")
        if len(parts) == 1:
            meta = dict(files_map[rel])
            meta["type"] = "file"
            meta["name"] = os.path.splitext(parts[0])[0]
            tree.append(meta)
        else:
            parent_nodes = ensure_dir(parts[:-1], tree)
            meta = dict(files_map[rel])
            meta["type"] = "file"
            meta["name"] = os.path.splitext(parts[-1])[0]
            parent_nodes.append(meta)

    return tree


def main():
    if len(sys.argv) < 4:
        print("Usage: python encrypt.py <password> <input_dir> <output_dir>")
        print("  Encrypts all files in <input_dir> and writes them to <output_dir>.")
        print("  A nested manifest.json (tree) is generated for the web page to read.")
        sys.exit(1)

    password = sys.argv[1]
    input_dir = sys.argv[2]
    output_dir = sys.argv[3]

    if not os.path.isdir(input_dir):
        print(f"Input directory not found: {input_dir}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    files = walk_dir(input_dir)
    files_map = {}

    for file_path in files:
        rel = os.path.relpath(file_path, input_dir).replace("\\", "/")
        out_name = rel + ".enc"
        out_path = os.path.join(output_dir, out_name)

        with open(file_path, "rb") as f:
            plain = f.read()

        enc = encrypt_bytes(plain, password)

        os.makedirs(os.path.dirname(out_path) or output_dir, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(enc)

        files_map[rel] = {
            "file": out_name,
            "mime": get_mime(file_path),
            "size": len(plain),
        }
        print(f"  Encrypted: {rel} -> {out_name}")

    manifest = build_tree(sorted(files_map.keys()), files_map, input_dir)

    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print(f"\nDone. {len(files)} files encrypted.")
    print(f"Manifest written to {manifest_path}")


if __name__ == "__main__":
    main()
