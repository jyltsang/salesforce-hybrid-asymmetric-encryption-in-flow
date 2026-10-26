@IsTest
private class FlowRSADataMaskingActionTest {

    private static FlowRSADataMaskingAction.MaskRequest req(List<SObject> recs) {
        FlowRSADataMaskingAction.MaskRequest r = new FlowRSADataMaskingAction.MaskRequest();
        r.recordsToMask = recs;
        r.fieldNamesCollection = new List<String>{'LastName', 'Email', 'MailingAddress'};
        r.encryptedLogFieldName = ' Description ';           // padding checks the trim
        r.statusCheckboxFieldName = ' HasOptedOutOfEmail ';
        return r;
    }

    private static List<FlowRSADataMaskingAction.MaskResult> run(FlowRSADataMaskingAction.MaskRequest r) {
        return FlowRSADataMaskingAction.processRecords(new List<FlowRSADataMaskingAction.MaskRequest>{r});
    }

    @IsTest
    static void queuesBatchForValidRecords() {
        RSAMaskBatch.testConfigs = new List<RSA_Key_Config__mdt>{
            new RSA_Key_Config__mdt(DeveloperName = 'Default_Key',
                Modulus__c = 'f'.repeat(512), Exponent__c = '10001')};
        Contact c = new Contact(LastName = 'Smith', Email = 'a@b.com');
        insert c;

        Test.startTest();
        List<FlowRSADataMaskingAction.MaskResult> out = run(req(new List<SObject>{c}));
        Test.stopTest();

        System.assertEquals(true, out[0].isSuccess);
        System.assert(out[0].message.startsWith('QUEUED: 1 record(s)'));
    }

    @IsTest
    static void rejectsEmptyAndNullCollections() {
        List<FlowRSADataMaskingAction.MaskResult> out =
            FlowRSADataMaskingAction.processRecords(new List<FlowRSADataMaskingAction.MaskRequest>{
                req(new List<SObject>()), req(null), null});
        System.assertEquals(3, out.size());
        for (FlowRSADataMaskingAction.MaskResult r : out) {
            System.assertEquals(false, r.isSuccess);
            System.assert(r.message.contains('empty'));
        }
    }

    @IsTest
    static void rejectsBlankLogOrStatusFieldNames() {
        Contact c = new Contact(LastName = 'Smith');
        insert c;

        FlowRSADataMaskingAction.MaskRequest noLog = req(new List<SObject>{c});
        noLog.encryptedLogFieldName = null;
        FlowRSADataMaskingAction.MaskRequest noStatus = req(new List<SObject>{c});
        noStatus.statusCheckboxFieldName = '   ';

        for (FlowRSADataMaskingAction.MaskRequest r : new List<FlowRSADataMaskingAction.MaskRequest>{noLog, noStatus}) {
            FlowRSADataMaskingAction.MaskResult res = run(r)[0];
            System.assertEquals(false, res.isSuccess);
            System.assert(res.message.contains('required'));
        }
    }

    @IsTest
    static void rejectsMixedObjectTypes() {
        Contact c = new Contact(LastName = 'Smith');
        Account a = new Account(Name = 'Acme');
        insert c;
        insert a;

        FlowRSADataMaskingAction.MaskResult res = run(req(new List<SObject>{c, a}))[0];
        System.assertEquals(false, res.isSuccess);
        System.assert(res.message.contains('same object'));
    }

    @IsTest
    static void rejectsRecordsWithoutIds() {
        FlowRSADataMaskingAction.MaskResult res = run(req(new List<SObject>{new Contact(LastName = 'Unsaved')}))[0];
        System.assertEquals(false, res.isSuccess);
        System.assert(res.message.contains('valid IDs'));
    }

    @IsTest
    static void resolvesFieldNames() {
        System.assertEquals(0, FlowRSADataMaskingAction.resolveFieldNames(null).size());

        List<String> out = FlowRSADataMaskingAction.resolveFieldNames(new List<String>{
            ' Email ', '', null, 'MailingAddress', 'BILLINGADDRESS',
            'shippingaddress', 'OtherAddress', 'email', 'MailingStreet'});
        System.assertEquals(21, out.size());   // 1 + 4 x 5, duplicates removed
        System.assertEquals('Email', out[0]);
        System.assert(out.contains('MailingPostalCode'));
        System.assert(out.contains('BillingCountry'));
        System.assert(out.contains('ShippingCity'));
        System.assert(out.contains('OtherStreet'));
    }
}
