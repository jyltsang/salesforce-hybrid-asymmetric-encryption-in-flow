public with sharing class FlowRSADataMaskingAction {

    public class MaskRequest {
        @InvocableVariable(required=true label='Object' description='Collection of records to encrypt')
        public List<SObject> recordsToMask;
        @InvocableVariable(required=true label='Fields Name' description='Collection of field API names to encrypt')
        public List<String> fieldNamesCollection;
        @InvocableVariable(required=true label='Log Field' description='API Name of the rich text log field')
        public String encryptedLogFieldName;
        @InvocableVariable(required=true label='Checkbox Field' description='API Name of the status checkbox field')
        public String statusCheckboxFieldName;
    }

    public class MaskResult {
        @InvocableVariable(label='Success Flag') public Boolean isSuccess;
        @InvocableVariable(label='Message') public String message;
    }

    // Compound address names (lower case) mapped to their component fields
    private static final Map<String, List<String>> COMPOUND_ADDRESSES = new Map<String, List<String>>{
        'mailingaddress'  => new List<String>{'MailingStreet', 'MailingCity', 'MailingState', 'MailingPostalCode', 'MailingCountry'},
        'otheraddress'    => new List<String>{'OtherStreet', 'OtherCity', 'OtherState', 'OtherPostalCode', 'OtherCountry'},
        'billingaddress'  => new List<String>{'BillingStreet', 'BillingCity', 'BillingState', 'BillingPostalCode', 'BillingCountry'},
        'shippingaddress' => new List<String>{'ShippingStreet', 'ShippingCity', 'ShippingState', 'ShippingPostalCode', 'ShippingCountry'}
    };

    // Flow entry point: validates, then hands off to an async batch (one record per transaction)
    @InvocableMethod(label='Asymmetrical RSA Masking (Async)' description='Queues RSA hybrid masking; one record per batch scope.')
    public static List<MaskResult> processRecords(List<MaskRequest> requests) {
        List<MaskResult> results = new List<MaskResult>();
        for (MaskRequest req : requests) {
            MaskResult res = new MaskResult();
            try {
                if (req == null || req.recordsToMask == null || req.recordsToMask.isEmpty()) {
                    res.isSuccess = false;
                    res.message = 'ERROR: The record collection is empty.';
                } else if (String.isBlank(req.encryptedLogFieldName) || String.isBlank(req.statusCheckboxFieldName)) {
                    res.isSuccess = false;
                    res.message = 'ERROR: The log field and checkbox field names are required.';
                } else {
                    Schema.SObjectType firstType = req.recordsToMask[0].getSObjectType();
                    Boolean mixedTypes = false;
                    Set<Id> ids = new Set<Id>();
                    for (SObject s : req.recordsToMask) {
                        if (s.getSObjectType() != firstType) mixedTypes = true;
                        if (s.Id != null) ids.add(s.Id);
                    }

                    if (mixedTypes) {
                        res.isSuccess = false;
                        res.message = 'ERROR: All records must belong to the same object.';
                    } else if (ids.isEmpty()) {
                        res.isSuccess = false;
                        res.message = 'ERROR: Provided records must have valid IDs.';
                    } else {
                        Id jobId = Database.executeBatch(new RSAMaskBatch(
                            firstType.getDescribe().getName(), new List<Id>(ids),
                            resolveFieldNames(req.fieldNamesCollection),
                            req.encryptedLogFieldName.trim(),
                            req.statusCheckboxFieldName.trim()), 1);
                        res.isSuccess = true;
                        res.message = 'QUEUED: ' + ids.size() + ' record(s), batch job ' + jobId;
                    }
                }
            } catch (Exception e) {
                res.isSuccess = false;
                res.message = 'ERROR: ' + e.getMessage();
            }
            results.add(res);
        }
        return results;
    }

    // Expands compound address names, trims, drops blanks and removes duplicates (case-insensitive)
    public static List<String> resolveFieldNames(List<String> fieldNames) {
        List<String> resolved = new List<String>();
        if (fieldNames == null) return resolved;

        Set<String> seen = new Set<String>();
        for (String f : fieldNames) {
            if (String.isBlank(f)) continue;
            String name = f.trim();
            List<String> expanded = COMPOUND_ADDRESSES.get(name.toLowerCase());
            List<String> toAdd = (expanded != null) ? expanded : new List<String>{name};
            for (String n : toAdd) {
                if (seen.add(n.toLowerCase())) resolved.add(n);
            }
        }
        return resolved;
    }
}
