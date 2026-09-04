import os
import re
import sys
import json
import secrets

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


def first_heading(text: str) -> str | None:
    for line in text.splitlines():
        m = re.match(r"^#\s+(.+?)\s*$", line.strip())
        if m:
            return m.group(1).strip()
    return None


def base_name(filename: str) -> str:
    return os.path.splitext(os.path.basename(filename))[0]


def main():
    if len(sys.argv) < 4:
        print("Usage: python encrypt.py <password> <articles_dir> <output_dir>")
        print("  Encrypts every markdown article in <articles_dir> into <output_dir>.")
        print("  Writes an open content-index.json next to the output dir.")
        sys.exit(1)

    password = sys.argv[1]
    articles_dir = sys.argv[2].rstrip("/\\")
    output_dir = sys.argv[3].rstrip("/\\")

    if not os.path.isdir(articles_dir):
        print(f"Articles directory not found: {articles_dir}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    article_index = []

    for root, _dirs, files in os.walk(articles_dir):
        for filename in sorted(files):
            if not filename.lower().endswith((".md", ".markdown", ".txt")):
                continue

            abs_path = os.path.join(root, filename)
            rel_dir = os.path.relpath(root, articles_dir)
            rel_part = "" if rel_dir == "." else rel_dir.replace("\\", "/")

            with open(abs_path, "rb") as f:
                plain = f.read()

            enc = encrypt_bytes(plain, password)

            out_dir = os.path.join(output_dir, rel_dir)
            os.makedirs(out_dir, exist_ok=True)
            out_name = filename + ".enc"
            with open(os.path.join(out_dir, out_name), "wb") as f:
                f.write(enc)

            rel_src = ("/" + rel_part + "/" if rel_part else "/") + filename
            rel_dst = ("/" + rel_part + "/" if rel_part else "/") + out_name

            title = first_heading(plain.decode("utf-8", errors="replace")) or base_name(filename)
            url_path = output_dir + rel_dst  # rel_dst starts with "/"
            article_index.append({
                "title": title,
                "path": url_path,
            })
            print(f"  Encrypted: {rel_src.lstrip('/')} -> {output_dir}{rel_dst}")

    parent = os.path.dirname(output_dir) or "."
    with open(os.path.join(parent, "content-index.json"), "w", encoding="utf-8") as f:
        json.dump(article_index, f, indent=4, ensure_ascii=False)

    print(f"\nDone. {len(article_index)} articles encrypted.")
    print(f"Encrypted files -> {output_dir}")
    print(f"content-index.json -> {os.path.join(parent, 'content-index.json')}")


if __name__ == "__main__":
    main()
