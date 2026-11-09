# Reference: Flow inputs and masking rules

Every statement here is taken from `FlowRSADataMaskingAction.cls` and `RSAMaskBatch.cls`. See [verification.md](verification.md).

## Flow action: **Asymmetrical RSA Masking (Async)**

| Input | Required | Description |
|---|---|---|
| **Object** | Yes | Collection of records, all of the same object, each with an Id |
| **Fields Name** | Yes | Text collection of field API names. `MailingAddress`, `OtherAddress`, `BillingAddress` and `ShippingAddress` expand to their five component fields. Blank and duplicate names (case-insensitive) are dropped |
| **Log Field** | Yes | API name, typed as plain text, of an editable Text Area (Rich or Long) field |
| **Checkbox Field** | Yes | API name, typed as plain text, of an editable checkbox |
| **Batch Size** | No | Records per batch transaction. Blank gives 1. Values outside 1 to 200 are clamped |

| Output | Description |
|---|---|
| **Success Flag** | `True` when the job was queued |
| **Message** | `QUEUED: <n> record(s), batch size <k>, batch job <Id>` or `ERROR: <reason>` |

`QUEUED` means only that the batch was accepted. Check *Setup → Apex Jobs* for the outcome. Call the action once per collection, not inside a loop.

**Typing the Log Field and Checkbox Field.** Enter the field API names as plain text (for example `Masked__c`). If you select the field from a record variable, Flow passes the field's *value* (such as `false`), not its name. The action rejects this with an error naming the field (`FlowRSADataMaskingActionTest.rejectsFieldValuesPassedInsteadOfApiNames`).

## Validation done by the action (before queuing)

- The collection is not empty and all records share one object type, each with an Id.
- The checkbox field exists on the object, is a checkbox and is updateable.
- The log field exists, is a Text Area or Long Text Area, and is updateable.

## What the batch does

For each record in the scope (`RSAMaskBatch.execute`):

1. Skip it if the status checkbox is already ticked.
2. Build `field:value` lines (lower-case API name, `String.valueOf(value)`) for fields whose value is not null.
3. If there is at least one line: generate an AES-256 key, encrypt the lines (joined by newline) with it, wrap the key with the RSA public key, and write `<hex>::<base64>` to the log field.
4. Replace the original field values (table below), tick the checkbox, and update all records in the scope with a single `update`.

## How fields are masked

Blank, unknown and duplicate names are skipped rather than failing the job. The log and status fields are never masked, even if listed. Non-updateable, address (compound), geolocation, binary and `ANYTYPE` fields are skipped.

| Field | Replacement |
|---|---|
| Nillable (optional) | `null` |
| Required text, text area, phone, encrypted string | `*****` (cut to the field length if shorter) |
| Required email | `masked@masked.invalid` |
| Required URL | `https://masked.invalid` |
| Required checkbox | `false` |
| Required integer, long, number, currency, percent | `0` |
| Required date | 1900-01-01 |
| Required date/time | 1900-01-01 00:00 |
| Required time | 00:00 |
| Required picklist, lookup, other | Left unchanged: no safe placeholder. The record is still flagged as masked |

## Custom Metadata

| Object | Field | Type | Meaning |
|---|---|---|---|
| `RSA_Key_Config__mdt` | `Modulus__c` | Text Area (Long) | RSA modulus as 512 lower- or upper-case hex characters. The batch fails if the length is not 512 |
| | `Exponent__c` | Text (20) | Public exponent in hex, for example `10001` |

Record: developer name `Default_Key`. The batch reads it with SOQL. The author reports that `getInstance()` returned the long modulus truncated to 255 characters, which is why SOQL is used; this has not been re-tested for this documentation.

## Offline decryption

```bash
python decrypt_envelope.py --key private_key.pem --file envelope.txt
```

- Without `--file` the envelope is read from standard input.
- `--password` prompts for a PEM passphrase.
- HTML tags, entities and whitespace in the pasted value are removed before decoding.
- Output is the plaintext: one `lowercasefieldname:value` line per masked field.
- If the envelope does not match the key, the script exits with `Decryption failed: the envelope doesn't match this private key…`.
