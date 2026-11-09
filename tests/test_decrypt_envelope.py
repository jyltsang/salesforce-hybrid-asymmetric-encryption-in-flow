"""Self-test for decrypt_envelope.py.

The envelope is built the way RSAMaskBatch.execute builds it:
  1. a random 32-byte AES key encrypts the payload (AES-256-CBC, PKCS7, IV prepended);
  2. the key, read as a big-endian integer, is raised to the public exponent modulo the
     modulus (raw RSA, no padding) and written as lower-case hex without leading zeros;
  3. the log value is '<rsa hex>::<base64(IV + ciphertext)>'.

This checks that the script agrees with that format. It does not run any Apex, so it is not
proof that the Salesforce side produces the same bytes.
"""
import base64
import os
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import decrypt_envelope  # noqa: E402

PAYLOAD = "lastname:Example\nemail:person@example.com\nmailingstreet:1 Test Street"


def make_envelope(public_numbers, payload, aes_key=None):
    aes_key = aes_key or os.urandom(32)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    blob = iv + enc.update(padded) + enc.finalize()
    wrapped = pow(int.from_bytes(aes_key, "big"), public_numbers.e, public_numbers.n)
    return "%x::%s" % (wrapped, base64.b64encode(blob).decode())


class DecryptEnvelopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pem = cls._write(cls.key, "key.pem")
        cls.other_pem = cls._write(cls.other, "other.pem")
        cls.encrypted_pem = cls._write(
            cls.key, "enc.pem", serialization.BestAvailableEncryption(b"test-passphrase"))

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    @classmethod
    def _write(cls, key, name, encryption=None):
        path = os.path.join(cls.dir.name, name)
        with open(path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                encryption or serialization.NoEncryption()))
        return path

    def test_round_trip(self):
        envelope = make_envelope(self.key.public_key().public_numbers(), PAYLOAD)
        self.assertEqual(PAYLOAD, decrypt_envelope.decrypt(envelope, self.pem))

    def test_aes_key_with_leading_zero_bytes(self):
        aes_key = b"\x00\x00" + os.urandom(30)
        envelope = make_envelope(self.key.public_key().public_numbers(), PAYLOAD, aes_key)
        self.assertEqual(PAYLOAD, decrypt_envelope.decrypt(envelope, self.pem))

    def test_rich_text_wrapping_and_whitespace_are_ignored(self):
        envelope = make_envelope(self.key.public_key().public_numbers(), PAYLOAD)
        rsa_hex, b64 = envelope.split("::")
        wrapped = "<p>%s::</p><p>%s</p>" % (rsa_hex, "\n".join(
            b64[i:i + 40] for i in range(0, len(b64), 40)))
        self.assertEqual(PAYLOAD, decrypt_envelope.decrypt(wrapped, self.pem))

    def test_unicode_payload(self):
        payload = "lastname:Zoë 東京"
        envelope = make_envelope(self.key.public_key().public_numbers(), payload)
        self.assertEqual(payload, decrypt_envelope.decrypt(envelope, self.pem))

    def test_passphrase_protected_key(self):
        envelope = make_envelope(self.key.public_key().public_numbers(), PAYLOAD)
        self.assertEqual(
            PAYLOAD, decrypt_envelope.decrypt(envelope, self.encrypted_pem, "test-passphrase"))

    def test_wrong_private_key_exits_with_a_clear_message(self):
        envelope = make_envelope(self.key.public_key().public_numbers(), PAYLOAD)
        with self.assertRaises(SystemExit) as ctx:
            decrypt_envelope.decrypt(envelope, self.other_pem)
        self.assertIn("doesn't match this private key", str(ctx.exception))

    def test_altered_ciphertext_is_not_silently_accepted_as_the_original(self):
        # AES-CBC without a MAC: a changed byte may produce garbage or a padding error,
        # but it must never return the original payload.
        envelope = make_envelope(self.key.public_key().public_numbers(), PAYLOAD)
        rsa_hex, b64 = envelope.split("::")
        blob = bytearray(base64.b64decode(b64))
        blob[-1] ^= 0x01
        tampered = "%s::%s" % (rsa_hex, base64.b64encode(bytes(blob)).decode())
        try:
            result = decrypt_envelope.decrypt(tampered, self.pem)
        except Exception:
            return
        self.assertNotEqual(PAYLOAD, result)


if __name__ == "__main__":
    unittest.main()
