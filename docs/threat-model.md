# Threat model: salesforce-hybrid-asymmetric-encryption-in-flow

This extends the summary in the [README](../README.md#threat-model). It describes what the code does and does not defend against. It is an analysis by the repository author's documentation pass, not an independent assessment. No independent cryptographic or security review has been done.

## 1. Scope and assumptions

**In scope:** `FlowRSADataMaskingAction`, `RSAMaskBatch`, `BigInt`, the `RSA_Key_Config__mdt` record, the log field and checkbox, and `decrypt_envelope.py`.

**Out of scope:** Salesforce platform security, the Flow that calls the action, approval processes, backups, integrations, the offline workstation's hardening, and the legal basis for retention or masking.

**Assumptions**

| # | Assumption | If false |
|---|---|---|
| A1 | The public key in `Default_Key` was derived from a private key that only the data owner holds, and was entered correctly before the first run | Envelopes are readable by someone else, or unreadable by anyone |
| A2 | The private key is stored securely and backed up outside Salesforce | Data is exposed (theft) or lost (loss) |
| A3 | `Crypto.encryptWithManagedIV('AES256', …)` behaves as `decrypt_envelope.py` assumes (CBC, PKCS7, IV prepended) | The script fails to decrypt. The author reports a successful manual end-to-end run, not evidenced in the repository |
| A4 | The Flow passes the intended records and fields | Wrong data is masked, or PI is left in place |
| A5 | Masking happens before the original values are copied elsewhere | Unmasked copies remain |

## 2. Data flow and trust boundaries

```
[Flow] --(1)--> [FlowRSADataMaskingAction] --(2)--> [RSAMaskBatch] --(3)--> [Record: log field + masked fields]
                                                       ^
                                                       | (4) SOQL
                                          [RSA_Key_Config__mdt Default_Key]

                    ===== boundary B1: Salesforce org | offline workstation =====

[Log field value] --(5, manual copy)--> [decrypt_envelope.py] <--(6)-- [private_key.pem]  --> plaintext
```

| Boundary | What crosses it | Control in this repository |
|---|---|---|
| B1 org / workstation | Envelope (into the workstation). Never the private key. | `.gitignore` excludes `*.pem` and `envelope*.txt`. Manual process; nothing enforces it |
| B2 Flow / Apex | Record collection and four strings | Input validation in `processRecords` and `controlFieldError`, and again in `RSAMaskBatch.execute` |
| B3 admin / data | Edit rights to the key record, Apex and Flow | None in this repository. Relies on org permissions |
| B4 record / log field | The envelope, stored in a normal editable field | None. Field edit permission governs it |

## 3. Scenarios

| ID | Scenario | Actor | Effect | Current defence | Residual |
|---|---|---|---|---|---|
| T1 | Public key replaced with the attacker's before the next run | Admin or deployer, or stolen admin session | All subsequent envelopes are readable by the attacker | None. No fingerprint check or signed configuration | High |
| T2 | Public key replaced accidentally (wrong paste) | Admin | Data becomes unrecoverable with the real private key | Length check (512 hex characters) catches truncation only | Medium |
| T3 | Log field overwritten or cleared after masking | User with edit access to the field, or integration | Permanent loss of the only copy of the PI | None | High; use field permissions and keep backups |
| T4 | Ciphertext modified | As T3 | Output is garbage, a padding error, or (rarely) a plausible but wrong value. No authenticated detection | None by design | High |
| T5 | Offline decryption by someone who obtains the private key | Anyone with the PEM | Full decryption of every envelope for that key | Passphrase option in the script, if the PEM was created with one | Depends on key storage |
| T6 | Chosen-ciphertext or structure attacks on raw RSA | Cryptanalyst with decryption oracle | Not applicable unless an oracle exists. The decryptor runs offline, but the lack of padding is a weakness in itself | None | Unassessed |
| T7 | Org data exported before masking | Insider with export rights | Plaintext already out | Out of scope | High; process control, not code |
| T8 | Masking silently fails | Misconfiguration (bad key length, missing key, validation rule) | Records stay in clear while the Flow reports `QUEUED` | Apex Jobs only | High for operations |
| T9 | PI left in a record marked as masked | Required picklist or lookup fields, or compound fields | Record has the checkbox ticked but still holds some PI | Documented in the README | Medium |
| T10 | Debug logs capture values | Anyone with debug log access | PI exposure | The code logs only a field name and type, and CPU time. No values or keys | Low from this code, but platform debug logs may capture other things |
| T11 | Dynamic SOQL injection through field names | Flow author | Unintended query | Status and log field names are checked against the object's describe map; target field names are used only if they exist in it | Low |
| T12 | Chunk-wide failure | Validation rule fails on one record | All records in that chunk are not masked | Default chunk size of 1 | Medium |
| T13 | Private key lost | Operator | Permanent data loss | None | High; operational |

## 4. STRIDE by component

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| **FlowRSADataMaskingAction** | Not applicable (runs as the caller) | Flow author can pass any field names; validated | Returns a message only | Error messages name fields, not values | Batch size clamped to 200 | `with sharing`; no explicit CRUD check |
| **RSAMaskBatch** | Key record can be swapped (T1) | Writes the envelope with a plain `update` | No audit of who masked what beyond platform job records | Original values held in memory during `execute`; envelope is the only retained copy | Heavy CPU per record; unmeasured | No user-mode query; update permission checked on target fields |
| **BigInt** | n/a | n/a | n/a | Not constant-time; operates on public values and the AES key (the base) | Slow for large inputs | n/a |
| **RSA_Key_Config__mdt** | Edited by whoever has metadata access | Same | Setup audit trail (platform) | Public by design | Missing or short modulus stops the batch | n/a |
| **decrypt_envelope.py** | Trusts the file it is given | Accepts altered ciphertext and may print garbage | n/a | Prints plaintext to the terminal | n/a | Runs with the user's rights |

## 5. Mitigations that are not implemented (suggestions)

These are ideas, not features of the repository, and they are listed so the gap is visible.

- Replace raw RSA with RSA-OAEP, and authenticate the payload (an AEAD mode or an HMAC). This may not be possible with Apex's built-in `Crypto` methods alone and needs investigation.
- Add a key identifier or fingerprint to each envelope, and a check that the configured public key matches an expected fingerprint stored elsewhere.
- Report batch outcomes back to the Flow's caller (for example with a custom log object or a platform event) and implement `finish()`.
- Use partial-save DML so one bad record does not fail a chunk.
- Query and update in user mode, and add tests for users without field access.
- Add known-answer tests for 2048-bit `BigInt.modPow`, and a cross-language test vector that both Apex and Python decrypt.

## 6. Residual risk statement

After masking, the data is protected only to the extent that (a) the public key record is the right one, (b) the raw-RSA and CBC constructions are adequate in practice, which has not been reviewed, (c) the private key stays secret, and (d) no unmasked copy exists elsewhere. The project does not defend against a malicious or compromised administrator acting *before* masking, and it does not make tampering detectable.
