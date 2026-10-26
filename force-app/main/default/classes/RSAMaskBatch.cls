public with sharing class RSAMaskBatch implements Database.Batchable<Id> {

    private String objectName;
    private List<Id> recordIds;
    private List<String> targetFields;
    private String encField;
    private String statusField;

    // Lets tests supply key material, since custom metadata cannot be inserted in a test
    @TestVisible private static List<RSA_Key_Config__mdt> testConfigs;

    private static final String MASK = '*****';

    // Compound or binary types that cannot be written or masked directly
    private static final Set<Schema.DisplayType> UNSUPPORTED_TYPES = new Set<Schema.DisplayType>{
        Schema.DisplayType.ADDRESS, Schema.DisplayType.LOCATION,
        Schema.DisplayType.BASE64, Schema.DisplayType.ANYTYPE
    };

    public RSAMaskBatch(String objectName, List<Id> recordIds, List<String> targetFields,
                        String encField, String statusField) {
        this.objectName = objectName;
        this.recordIds = recordIds;
        this.targetFields = targetFields;
        this.encField = encField;
        this.statusField = statusField;
    }

    public Iterable<Id> start(Database.BatchableContext bc) {
        return recordIds;
    }

    public void execute(Database.BatchableContext bc, List<Id> scope) {
        List<RSA_Key_Config__mdt> cfgs = (testConfigs != null) ? testConfigs :
            [SELECT Modulus__c, Exponent__c
             FROM RSA_Key_Config__mdt
             WHERE DeveloperName = 'Default_Key' LIMIT 1];

        if (cfgs.isEmpty() || String.isBlank(cfgs[0].Modulus__c) || String.isBlank(cfgs[0].Exponent__c)) {
            throw new RSAMaskException('RSA_Key_Config__mdt Default_Key missing or incomplete.');
        }

        String modHex = cfgs[0].Modulus__c.trim();
        if (modHex.length() != 512) {
            throw new RSAMaskException('Modulus length is ' + modHex.length() + ', expected 512.');
        }

        BigInt modulus = new BigInt(modHex, 16);
        BigInt exponent = new BigInt(cfgs[0].Exponent__c.trim(), 16);

        Schema.SObjectType sot = Schema.getGlobalDescribe().get(objectName);
        Map<String, Schema.SObjectField> fieldMap = sot.getDescribe().fields.getMap();

        // Build the masking plan once: field name -> replacement value (null means clear the field)
        List<String> validFields = new List<String>();
        Map<String, Object> maskValues = new Map<String, Object>();
        String encLower = encField.trim().toLowerCase();
        String statusLower = statusField.trim().toLowerCase();

        if (targetFields != null) {
            for (String f : targetFields) {
                if (String.isBlank(f)) continue;
                String clean = f.trim().toLowerCase();
                if (!fieldMap.containsKey(clean) || maskValues.containsKey(clean)) continue;
                if (clean == encLower || clean == statusLower) continue;

                Schema.DescribeFieldResult d = fieldMap.get(clean).getDescribe();
                if (!d.isUpdateable() || UNSUPPORTED_TYPES.contains(d.getType())) continue;

                if (d.isNillable()) {
                    maskValues.put(clean, null);
                    validFields.add(clean);
                } else {
                    Object placeholder = requiredPlaceholder(d);
                    if (placeholder != null) {
                        maskValues.put(clean, placeholder);
                        validFields.add(clean);
                    } else {
                        System.debug('RSA mask: cannot mask required field ' + clean
                                     + ' of type ' + d.getType() + '; left unchanged.');
                    }
                }
            }
        }

        Set<String> queryFields = new Set<String>{'id', statusLower};
        queryFields.addAll(validFields);

        List<SObject> records = Database.query(
            'SELECT ' + String.join(new List<String>(queryFields), ', ') +
            ' FROM ' + objectName + ' WHERE Id IN :scope');

        List<SObject> toUpdate = new List<SObject>();
        for (SObject record : records) {
            // Idempotency: never re-mask an already masked record
            if ((Boolean) record.get(statusLower) == true) continue;

            List<String> lines = new List<String>();
            for (String clean : validFields) {
                Object raw = record.get(clean);
                if (raw != null) lines.add(clean + ':' + String.valueOf(raw));
                record.put(clean, maskValues.get(clean));
            }

            if (!lines.isEmpty()) {
                Blob aesKey = Crypto.generateAESKey(256);
                Blob cipher = Crypto.encryptWithManagedIV('AES256', aesKey,
                                  Blob.valueOf(String.join(lines, '\n')));
                BigInt m = new BigInt(EncodingUtil.convertToHex(aesKey), 16);
                BigInt c = m.modPow(exponent, modulus);
                record.put(encLower, c.toHex() + '::' + EncodingUtil.base64Encode(cipher));
            }

            record.put(statusLower, true);
            toUpdate.add(record);
        }

        if (!toUpdate.isEmpty()) update toUpdate;
        System.debug('RSA mask CPU ms: ' + Limits.getCpuTime());
    }

    // Valid replacement for a required (non-nillable) field; null means it cannot be masked safely
    @TestVisible
    private static Object requiredPlaceholder(Schema.DescribeFieldResult d) {
        Schema.DisplayType t = d.getType();
        if (t == Schema.DisplayType.STRING || t == Schema.DisplayType.TEXTAREA
            || t == Schema.DisplayType.PHONE || t == Schema.DisplayType.ENCRYPTEDSTRING) {
            Integer len = d.getLength();
            return (len > 0 && len < MASK.length()) ? MASK.left(len) : MASK;
        }
        if (t == Schema.DisplayType.EMAIL)    return 'masked@masked.invalid';
        if (t == Schema.DisplayType.URL)      return 'https://masked.invalid';
        if (t == Schema.DisplayType.BOOLEAN)  return false;
        if (t == Schema.DisplayType.INTEGER)  return 0;
        if (t == Schema.DisplayType.LONG)     return 0L;
        if (t == Schema.DisplayType.DOUBLE || t == Schema.DisplayType.CURRENCY
            || t == Schema.DisplayType.PERCENT) return Decimal.valueOf(0);
        if (t == Schema.DisplayType.DATE)     return Date.newInstance(1900, 1, 1);
        if (t == Schema.DisplayType.DATETIME) return Datetime.newInstance(1900, 1, 1);
        if (t == Schema.DisplayType.TIME)     return Time.newInstance(0, 0, 0, 0);
        return null;   // required picklist, lookup and so on: no safe placeholder
    }

    public void finish(Database.BatchableContext bc) {}

    public class RSAMaskException extends Exception {}
}
