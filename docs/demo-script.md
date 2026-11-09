# Demo script: hybrid RSA-2048 and AES-256 masking (3 to 5 minutes)

**Recording link:** _placeholder, to be added after recording_

**Aim:** show that Salesforce holds only a public key, that masking replaces the PI with an envelope, and that only the offline private key recovers it.

## Before you record

- Use a **sandbox or scratch org** with made-up data only. The test steps in the [README](../README.md#test-steps) cover setup. Set it up fully first and rehearse once.
- Prepare one Contact: last name `Demo Person`, email `demo.person@example.com`, a made-up mailing street.
- Have these ready in separate windows: Setup → Custom Metadata (the `Default_Key` record), the Flow, the Contact record, Apex Jobs, and a terminal in the repository folder with the Python virtual environment active.
- Generate a **disposable** key pair for the demo (`openssl genrsa -out private_key.pem 2048`). Never show a key you use anywhere else.
- Hide anything that identifies an organisation: browser bookmarks and tabs, the org URL, user name and avatar, email addresses other than the dummy one. Crop or blur if needed. Do not record your real org.
- Close notifications. Use a large font in the terminal.

## Script

| Time | Say | Show |
|---|---|---|
| 0:00 | "This project masks personal data in Salesforce so that the key able to reverse the masking is never stored in the org. It is a proof of concept." | README title and the status banner |
| 0:20 | "A Flow passes records to an Apex action. A batch job encrypts each record's chosen fields with a fresh AES-256 key, then encrypts that key with an RSA public key." | The Mermaid diagram in the README |
| 0:50 | "Salesforce holds only the public key: a modulus and an exponent. The private key stays on this machine." | Custom Metadata record `Default_Key` (modulus and exponent only), then the terminal: `ls private_key.pem` (do not print its contents) |
| 1:15 | "Here is a dummy contact with an email and an address." | The Contact record before masking, with `Data_Masked__c` unticked |
| 1:30 | "The Flow collects the record and the field names, then calls the action. The log and checkbox names are typed as plain text." | The Flow canvas: Get Records, Assignment, the action's inputs |
| 1:55 | "I run it. The action only reports QUEUED, because the work is asynchronous." | Run the Flow; show the `QUEUED: 1 record(s), batch size 1, batch job …` message |
| 2:15 | "The real outcome is in Apex Jobs." | Setup → Apex Jobs, the `RSAMaskBatch` job Completed |
| 2:30 | "The email and address are gone, the last name is a placeholder, the box is ticked, and the log holds the envelope: RSA hex, two colons, then base64." | Refresh the Contact; point at the log field value (do not scroll through all of it) |
| 3:00 | "To read it back I copy the log value into a file and use the private key, offline." | Paste into `envelope.txt`, then run `python decrypt_envelope.py --key private_key.pem --file envelope.txt` |
| 3:30 | "The output lists each field with its original value. Field names are lower case." | Terminal output (dummy values only) |
| 3:45 | "A different key cannot do this." | Run the script with `other.pem` (a second throwaway key). Show the `Decryption failed: the envelope doesn't match this private key…` message |
| 4:05 | "This is raw RSA without padding, with a custom big-number class, and nobody independent has reviewed it. There is no in-org unmask, and losing the private key loses the data." | The Limitations heading in the README |
| 4:30 | "Tests, threat model and a claim-by-claim verification table are in the repository." | `docs/verification.md` open, then stop |

## After recording

- Delete the demo Contact, `envelope.txt`, `private_key.pem` and `other.pem` (or store them deliberately). Revert the sandbox key record.
- Check the recording frame by frame for any real name, email, org URL or identifier.
- Add the link at the top of this file and in the README's Demo section.
