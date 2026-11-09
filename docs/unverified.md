# Unverified items

These statements could not be confirmed from the code in this repository. The README either omits them or says clearly that they are unverified.

| ID | Item | Why it is unverified | How to close it |
|---|---|---|---|
| U1 | The Apex tests pass | The author reports that they passed. The repository holds no test log or coverage result, and no Salesforce org was available during this documentation pass | Run `sf apex run test --class-names BigIntTest --class-names RSAMaskBatchTest --class-names FlowRSADataMaskingActionTest --code-coverage --result-format human --wait 10` in a sandbox and keep the output |
| U2 | Envelopes made by Apex decrypt with `decrypt_envelope.py` (a real 2048-bit key, end to end) | The author reports a successful manual run. No artefact is in the repository. The Python test builds its own envelopes | Add a non-secret test vector: generate a throwaway key pair, mask a dummy record in a sandbox, store the public modulus, the resulting envelope and the expected plaintext,, then decrypt it locally with the throwaway private key. Keep that private key out of the repository (it would trigger secret scanners); commit only the public values and the expected plaintext, or generate the pair in a CI step |
| U3 | The retention Flow scenario (conditions, roll-up check, approval, scheduled next-run masking) | The Flow is not in the repository | Add a sanitised Flow export, or keep the scenario labelled as illustrative |
| U4 | `Crypto.encryptWithManagedIV('AES256', …)` produces CBC with PKCS7 padding and a prepended 16-byte IV | Documented Salesforce behaviour that this repository assumes. The README relies on the script working | Cite the current Salesforce Apex Reference, or add the cross-language test vector in U2 |
| U5 | The added metadata files (`sfdx-project.json`, `RSA_Key_Config__mdt` and its two fields) deploy cleanly | Not deployable here (no Salesforce CLI or org) | Run the deploy command in a sandbox |
| U6 | Platform statements: "Apex has no native RSA encryption", batch jobs run as the user who started them, sandbox refresh copies data | Not checked against Salesforce documentation | Cite the documentation, or remove the statement |
| U7 | The Flow click path and screen results in test steps section C | Written from the code and tests, not executed in an org | Follow the steps once and correct them |
| U8 | The Issues tab is enabled, and private vulnerability reporting is available | Repository settings are not visible from the code | Check the repository settings |
| U9 | The author's observation that `getInstance()` truncated the long modulus to 255 characters | Platform behaviour observed once, not re-tested here. The code uses SOQL | Re-test in a sandbox if the claim is to be repeated |
| U10 | Real-world use of the approach in other orgs, or in other Salesforce clouds | Not evidenced by the repository. Deliberately not stated in the README | Leave out unless it can be shown without naming any organisation |
