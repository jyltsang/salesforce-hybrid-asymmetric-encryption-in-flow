# Verification: README claims against the repository

**Meaning of the status column**

- **Verified**: confirmed by reading the named file, function or test, or by a command run during this documentation pass (stated in the evidence).
- **Unverified**: not provable from the repository or from checks possible during this pass. Listed in [unverified.md](unverified.md) and not presented as fact in the README.

**Limits of this review.** No Salesforce org or Salesforce CLI was available, so no Apex was executed and nothing was deployed. "Verified" for an Apex test means the test source contains the stated assertion. It does not mean the test was run by the reviewer. The author reports that the Apex tests passed; no log or coverage report is in the repository (see U1). Python tests and `openssl` commands were run (Python 3.13, `cryptography` 50.0.1, OpenSSL 3.0.13).

| # | README claim | Evidence | Status |
|---|---|---|---|
| **Summary** | | | |
| 1 | A Flow passes records, field names, a log field and a status checkbox to an Apex invocable action | `FlowRSADataMaskingAction.MaskRequest` (`@InvocableVariable` fields); `@InvocableMethod processRecords` | Verified |
| 2 | The action validates input and queues a batch | `processRecords`, `controlFieldError`, `Database.executeBatch`; `FlowRSADataMaskingActionTest.queuesBatchForValidRecords`, `rejectsEmptyAndNullCollections`, `rejectsMixedObjectTypes` | Verified |
| 3 | The batch joins chosen field values into one text payload | `RSAMaskBatch.execute`: `String.join(lines, '\n')` | Verified |
| 4 | A fresh AES-256 key is generated for each record | `Crypto.generateAESKey(256)` inside the per-record loop | Verified |
| 5 | The AES key is encrypted with an RSA public key held in Custom Metadata | `RSAMaskBatch.execute`: SOQL on `RSA_Key_Config__mdt`, `BigInt.modPow(exponent, modulus)` | Verified |
| 6 | The log field receives `<RSA hex>::<AES payload base64>` | `RSAMaskBatch.execute` (`c.toHex() + '::' + EncodingUtil.base64Encode(cipher)`); `RSAMaskBatchTest.runsEndToEndThroughBatchApi` asserts `contains('::')` | Verified |
| 7 | Original fields are blanked or replaced and the status checkbox is ticked | `RSAMaskBatch.execute`; `RSAMaskBatchTest.runsEndToEndThroughBatchApi` | Verified |
| 8 | The private key is never in Salesforce and there is no in-org unmask | Search of all non-test Apex finds no decryption call and no private-key handling | Verified (by absence) |
| 9 | `decrypt_envelope.py` decrypts an envelope given the private key | `decrypt_envelope.py`; `tests/test_decrypt_envelope.py::test_round_trip` (executed: pass) | Verified, against envelopes built in Python |
| 10 | Envelopes written by the Apex code decrypt with the script | No test crosses the Apex and Python sides | Unverified (U2) |
| **Use cases** | | | |
| 11 | The retention Flow scenario (conditions, roll-up check, approval, next run) | The Flow is not in the repository | Unverified (U3) |
| 12 | Processing is asynchronous and the RSA arithmetic runs in Apex | `Database.executeBatch`; `BigInt.modPow` | Verified |
| 13 | The repository contains no performance measurements | Absence; only `System.debug('RSA mask CPU ms: …')` | Verified (by absence) |
| 14 | A party able to edit the key record can redirect future envelopes | `RSAMaskBatch.execute` reads `Default_Key` with no integrity or fingerprint check | Verified |
| **Architecture** | | | |
| 15 | Components in the diagram exist as described | The four classes, the Custom Metadata type and the script exist | Verified |
| 16 | Plaintext is one lower-case `field:value` line per field, newline-joined | `RSAMaskBatch.execute` (`clean + ':' + String.valueOf(raw)`, `clean` is lower case) | Verified |
| 17 | Field names are inside the ciphertext | Same code: names are only in the encrypted payload | Verified |
| 18 | Envelope is `IV(16) \|\| AES-256-CBC (PKCS7)` as `AES256` managed IV produces | The script assumes it; the Apex call is `Crypto.encryptWithManagedIV('AES256', …)`; Salesforce behaviour not checked | Unverified (U4) |
| **Key handling** | | | |
| 19 | The private key lives offline; `*.pem` is git-ignored | `.gitignore` | Verified |
| 20 | Modulus must be 512 hex characters; exponent is `10001` | `RSAMaskBatch.execute` length check; `RSAMaskBatchTest.failsWhenKeyMissingOrInvalid`. `openssl genrsa … 2048` yields a 512-character modulus and `publicExponent: 65537 (0x10001)` (run in this pass) | Verified |
| 21 | `Default_Key` record, `Modulus__c` and `Exponent__c` fields | `RSAMaskBatch.execute`; metadata files added in this change | Verified for the code. The added metadata files were not deployed (U5) |
| 22 | The AES key exists only in memory, is not logged | The only `System.debug` calls print a field name and type, and CPU time | Verified |
| 23 | Tests use a dummy modulus, not a real key | `RSAMaskBatchTest.useValidKey` (`'f'.repeat(512)`) | Verified |
| 24 | No rotation; only `Default_Key` is read; no key id in the envelope | SOQL `WHERE DeveloperName = 'Default_Key'`; envelope format | Verified |
| 25 | The script supports a passphrase-protected PEM | `--password` in `decrypt_envelope.py`; `test_passphrase_protected_key` (executed: pass) | Verified |
| **Threat model** | | | |
| 26 | Classes use `with sharing` | Class declarations of all three Apex classes | Verified |
| 27 | Update permission on fields is checked; the query is not in user mode; no CRUD check | `controlFieldError`, `RSAMaskBatch.execute` (`isUpdateable`, `Database.query` without user mode) | Verified |
| 28 | Batch size defaults to 1 and is clamped to 1–200 | `resolveBatchSize`; `FlowRSADataMaskingActionTest.resolvesBatchSize` | Verified |
| 29 | Batch failures are not reported to the Flow; `finish()` does nothing | `RSAMaskBatch.finish`; action returns `QUEUED` | Verified |
| 30 | A DML failure fails the whole chunk | `update toUpdate;` (not partial save) | Verified |
| 31 | No MAC or authentication on the envelope | No HMAC or AEAD code present | Verified for the code; CBC behaviour per U4 |
| 32 | Altered ciphertext is not returned as the original | `test_altered_ciphertext_is_not_silently_accepted_as_the_original` (executed: pass) | Verified (one case, Python only) |
| 33 | Field names in dynamic SOQL are validated against describe data | `RSAMaskBatch.execute`; `RSAMaskBatchTest.rejectsInvalidStatusOrLogFieldBeforeQuerying` | Verified |
| 34 | Required picklist and lookup fields are left unchanged but the record is still flagged | `RSAMaskBatch.requiredPlaceholder` returns null for them; `placeholdersMatchFieldTypes` | Verified |
| 35 | Placeholders are visible (`*****`, `masked@masked.invalid`, 1900-01-01) | `RSAMaskBatch.requiredPlaceholder` | Verified |
| 36 | A ticked checkbox with no log can mean no values, or no maskable fields | `RSAMaskBatchTest.flagsRecordWhenNothingToEncrypt`; `RSAMaskBatch.execute` | Verified |
| **Design decisions** | | | |
| 37 | The AES repository was written first | First commits dated 2026-09-27 (AES) and 2026-09-28 (hybrid) in `git log` | Verified |
| 38 | The AES repository keeps its key in Custom Metadata and unmasks in-org | `FlowAES256Util.getKey`, `FlowAES256DataUnmaskingAction` in that repository | Verified |
| 39 | RSA wraps only the 32-byte key; AES encrypts the payload | `RSAMaskBatch.execute` | Verified |
| 40 | Apex has no native RSA encryption | Stated in the previous README; platform documentation not checked | Unverified (U6) |
| 41 | 388 lines of Apex excluding tests | `wc -l` on `BigInt.cls`, `FlowRSADataMaskingAction.cls`, `RSAMaskBatch.cls` (92 + 139 + 157) | Verified |
| 42 | Values lose their type and multi-line values are ambiguous | `String.valueOf(raw)`; newline join | Verified |
| **Limitations** | | | |
| 43 | Raw RSA without padding | `RSAMaskBatch.execute` exponentiates the AES key directly; `BigIntTest.textbookRsaRoundTrip` | Verified |
| 44 | `BigInt` tests use toy values, an 89-bit Mersenne modulus, and the batch tests use a dummy 2048-bit modulus | `BigIntTest`, `RSAMaskBatchTest` | Verified |
| 45 | No known-answer test at 2048 bits; no Apex-to-Python test | Absence | Verified (by absence) |
| 46 | `BigInt` is not constant-time | Conditional multiply in `modPow` | Verified by reading; not analysed further |
| 47 | No restore tool, no key escrow or recovery | Absence | Verified (by absence) |
| 48 | Code does not handle field history, files, notes, exports or integrations | Search of Apex for `History`, `ContentDocument`, `Note` finds nothing | Verified (by absence) |
| 49 | Batch runs as the starting user; sandbox refresh copies data and metadata | Platform behaviour | Unverified (U6) |
| 50 | No independent cryptographic review has been done | Author's statement | Author-confirmed |
| 51 | No Flow is included | File list | Verified |
| **Test steps** | | | |
| 52 | 22 Apex test methods in three classes | Count of `@IsTest` methods: 5 + 8 + 9 | Verified (counted) |
| 53 | All Apex tests pass | The author reports a pass; no log or coverage report in the repository | Unverified (U1) |
| 54 | 7 Python tests pass | `python3 -m unittest discover -s tests -v`: `Ran 7 tests … OK` (Python 3.13) | Verified (executed) |
| 55 | Tests use standard Contact fields and a dummy key | `RSAMaskBatchTest`, `FlowRSADataMaskingActionTest` | Verified |
| 56 | The deploy commands succeed and the added metadata deploys | Not run | Unverified (U5) |
| 57 | Message begins `QUEUED: 1 record(s), batch size 1,` | `FlowRSADataMaskingActionTest.queuesBatchForValidRecords` | Verified |
| 58 | Running the Flow twice leaves the record unchanged | `RSAMaskBatchTest.skipsAlreadyMaskedRecords` | Verified |
| 59 | A wrong private key gives `Decryption failed: the envelope doesn't match this private key…` | `decrypt_envelope.py`; `test_wrong_private_key_exits_with_a_clear_message` (executed: pass) | Verified |
| 60 | The Flow click path and screen results in section C of the test steps | Not executed in any org during this pass | Unverified (U7) |
| 61 | The author completed an end-to-end run with a real key and decrypted it | Author's statement; no artefact | Unverified (U2) |
| **Other sections** | | | |
| 62 | `LICENSE` exists (MIT) | `LICENSE` in the repository root | Verified |
| 63 | Security reports can be made through the repository's Issues tab | Depends on a repository setting not checked here | Unverified (U8) |
