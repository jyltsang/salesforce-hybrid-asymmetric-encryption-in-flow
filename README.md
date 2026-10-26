# salesforce-hybrid-asymmetric-encryption-in-flow

Mask personal information (PI) in Salesforce using RSA-2048 + AES-256. Salesforce holds only the **public key**; the **private key stays offline**. If the org's data and metadata are exported, the masked values cannot be decrypted.

A follow-up to [salesforce-aes256-data-masking-in-flow](https://github.com/jyltsang/salesforce-aes256-data-masking-in-flow).

## How it works

1. A Flow passes a record collection to the Apex action.
2. The action queues a batch job (chunk size set in the Flow).
3. For each record, the batch:
   - joins the chosen field values into one text payload,
   - encrypts it with a random AES-256 key,
   - encrypts that AES key with your RSA public key,
   - stores `<RSA hex>::<AES payload base64>` in the log field,
   - masks the original fields (see *How fields are masked*) and ticks the status checkbox.
4. You decrypt off-platform with the private key.

## Why not AES only?

| | AES only | This project |
|---|---|---|
| Key in Salesforce | Yes (admins and Apex can read it) | Public key only |
| Org compromise exposes data | Yes | No |
| Unmask inside Salesforce | Yes | No (offline only) |

## Files

- `FlowRSADataMaskingAction.cls`: invocable action for Flow; validates input and queues the batch
- `RSAMaskBatch.cls`: masks and encrypts records
- `BigInt.cls`: big-number maths for RSA (Apex has no native RSA encryption)
- `BigIntTest.cls`, `RSAMaskBatchTest.cls`, `FlowRSADataMaskingActionTest.cls`: unit tests (Salesforce requires 75% coverage to deploy to production)
- `decrypt_envelope.py`: offline decryption

## Setup

### 1. Generate the keys (off-platform)

```bash
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -noout -modulus | cut -d= -f2
```

The second command prints the modulus (512 hex characters). The exponent is `10001`. Keep `private_key.pem` offline and never upload it.

### 2. Create the custom metadata

Setup → Custom Metadata Types → New:

- Label: `RSA Key Config`, Object Name: `RSA_Key_Config`
- Fields:
  - `Modulus__c`: **Text Area (Long)**
  - `Exponent__c`: Text (20)
- Manage Records → New: Name `Default_Key`, Modulus = the 512 characters, Exponent = `10001`

A plain Text field truncates the modulus to 255 characters. The batch checks the length and fails if it isn't 512.

### 3. Create fields on the target object

- **Log field:** Text Area (Rich), 131,072 characters
- **Status field:** Checkbox

### 4. Deploy the Apex classes

Deploy `BigInt`, `RSAMaskBatch` and `FlowRSADataMaskingAction`, together with the three test classes:

```bash
sf project deploy start --source-dir force-app --test-level RunLocalTests
```

The tests use standard Contact fields and inject a dummy key through `RSAMaskBatch.testConfigs`, so they do not depend on your `Default_Key` record. If your org has required custom fields, validation rules or triggers on Contact, add the required values in `RSAMaskBatchTest.makeContact`.

### 5. Build the Flow

Get the records, put the field API names into a text collection, then add the action **Asymmetrical RSA Masking (Async)**:

| Input | Value |
|---|---|
| Object | Record collection |
| Fields Name | Text collection of field API names (`MailingAddress`, `OtherAddress`, `BillingAddress` and `ShippingAddress` expand to their parts) |
| Log Field | API name of the rich text log field |
| Checkbox Field | API name of the status checkbox |
| Batch Size | Optional, 1 to 200, default 1. Smaller chunks give each record more CPU headroom |

Call the action once per collection, not inside a loop.

### 6. How fields are masked

Any field type can be listed. Blank, unknown and duplicate names are skipped rather than failing the job. The log and status fields are never masked, even if listed.

| Field | Replacement |
|---|---|
| Nillable (optional) | `null` |
| Required text, text area, phone | `*****` (cut to the field length if shorter) |
| Required email / URL | `masked@masked.invalid` / `https://masked.invalid` |
| Required checkbox, number, currency, percent | `false` / `0` |
| Required date, date/time, time | 1900-01-01 / 1900-01-01 00:00 / 00:00 |
| Required picklist, lookup | Left unchanged (no safe placeholder); the record is still flagged |
| Not updateable, address, geolocation, binary | Skipped |

### 7. Check the result

The action returns `QUEUED`, which only means the job was accepted. Check **Setup → Apex Jobs** for the real outcome. Already masked records are skipped.

## Decrypt (off-platform)

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install cryptography
python decrypt_envelope.py --key private_key.pem --file envelope.txt
```

Paste the log field value into `envelope.txt`. Add `--password` if the PEM is passphrase-protected. Output is one `fieldname:value` line per masked field, with lowercase API names.

## Limitations

- **No OAEP padding.** The AES key is wrapped with raw (textbook) RSA. Treat this as a proof of concept until it has been security reviewed.
- **Slow big-number maths in Apex.** This is why masking runs in an async batch with small chunks. Benchmark in your own org.
- **`getInstance()` truncated the long modulus to 255 characters in testing**, so the batch reads it with SOQL.
- **Losing the private key means the data cannot be recovered.**
