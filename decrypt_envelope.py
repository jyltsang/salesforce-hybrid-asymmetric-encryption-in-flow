#!/usr/bin/env python3
"""Decrypt a Salesforce RSA/AES envelope: <rsaHex>::<base64 AES blob>"""
import argparse, base64, getpass, html, re, sys
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def clean(raw: str) -> str:
    """The log field is rich text, so strip any HTML tags and entities."""
    text = re.sub(r"<[^>]+>", "", raw)
    text = html.unescape(text)
    return re.sub(r"\s+", "", text)          # remove stray whitespace/newlines


def decrypt(envelope, pem_path, password=None):
    with open(pem_path, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=password.encode() if password else None)
    nums = key.private_numbers()
    n, d = nums.public_numbers.n, nums.d

    rsa_hex, b64 = clean(envelope).split("::", 1)

    # 1. Raw RSA: recover the 32-byte AES session key
    try:
        aes_key = pow(int(rsa_hex, 16), d, n).to_bytes(32, "big")
    except OverflowError:
        sys.exit("Decryption failed: the envelope doesn't match this private key "
                 "(wrong key pair, or the Salesforce modulus/exponent is incorrect).")

    # 2. AES-256-CBC: managed IV = first 16 bytes, PKCS7 padding
    blob = base64.b64decode(b64)
    iv, ct = blob[:16], blob[16:]
    dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", default="private_key.pem", help="path to private key PEM")
    ap.add_argument("--file", help="text file containing the envelope (default: read stdin)")
    ap.add_argument("--password", action="store_true", help="prompt for PEM passphrase")
    args = ap.parse_args()

    envelope = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    pw = getpass.getpass("PEM passphrase: ") if args.password else None
    print(decrypt(envelope, args.key, pw))