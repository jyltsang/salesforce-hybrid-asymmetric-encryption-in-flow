@IsTest
private class RSAMaskBatchTest {

    private static final String LOG_FIELD = 'Description';
    private static final String FLAG_FIELD = 'HasOptedOutOfEmail';

    private static void useValidKey() {
        RSAMaskBatch.testConfigs = new List<RSA_Key_Config__mdt>{
            new RSA_Key_Config__mdt(
                DeveloperName = 'Default_Key',
                Modulus__c = 'f'.repeat(512),   // 2048-bit test modulus (not a real key)
                Exponent__c = '10001')
        };
    }

    private static Contact makeContact(Boolean alreadyMasked) {
        Contact c = new Contact(
            LastName = 'Smith', Email = 'john@example.com', Phone = '0131 496 0000',
            MailingStreet = '1 High Street', MailingCity = 'Edinburgh',
            MailingPostalCode = 'EH1 1AA', MailingCountry = 'United Kingdom',
            Birthdate = Date.newInstance(1990, 1, 1), DoNotCall = true,
            HasOptedOutOfEmail = alreadyMasked);
        insert c;
        return c;
    }

    private static List<String> fields() {
        return new List<String>{
            'LastName', 'Email', 'Phone', 'MailingStreet', 'MailingCity',
            'MailingPostalCode', 'MailingCountry', 'Title', 'Birthdate', 'DoNotCall',
            'ReportsToId', 'MailingAddress', 'CreatedDate',
            'Description', 'HasOptedOutOfEmail',   // log and status fields must never be masked
            '', 'NoSuchField__c', 'email'          // blank, unknown and duplicate names
        };
    }

    @IsTest
    static void runsEndToEndThroughBatchApi() {
        useValidKey();
        Contact c = makeContact(false);

        Test.startTest();
        Database.executeBatch(new RSAMaskBatch('Contact', new List<Id>{c.Id}, fields(), LOG_FIELD, FLAG_FIELD), 1);
        Test.stopTest();

        Contact after = [SELECT LastName, Email, Phone, MailingStreet, Birthdate, DoNotCall,
                                HasOptedOutOfEmail, Description
                         FROM Contact WHERE Id = :c.Id];
        System.assertEquals('*****', after.LastName, 'Required text field gets the mask');
        System.assertEquals(null, after.Email);
        System.assertEquals(null, after.Phone);
        System.assertEquals(null, after.MailingStreet);
        System.assertEquals(null, after.Birthdate);
        System.assertEquals(false, after.DoNotCall, 'Required checkbox gets a valid placeholder');
        System.assertEquals(true, after.HasOptedOutOfEmail);
        System.assert(after.Description.contains('::'), 'Log should hold RSA key and AES cipher text');
        // Original values must not reach the log in plain text. The email and street contain
        // '@' and spaces, which hex and base64 never produce, so ciphertext can never match them by chance
        System.assert(!after.Description.contains('Smith'), 'Log must not hold the plain last name');
        System.assert(!after.Description.contains('john@example.com'), 'Log must not hold the plain email');
        System.assert(!after.Description.contains('1 High Street'), 'Log must not hold the plain street');
    }

    @IsTest
    static void startReturnsRecordIds() {
        Contact c = makeContact(false);
        RSAMaskBatch b = new RSAMaskBatch('Contact', new List<Id>{c.Id}, fields(), LOG_FIELD, FLAG_FIELD);
        System.assertNotEquals(null, b.start(null));
    }

    @IsTest
    static void skipsAlreadyMaskedRecords() {
        useValidKey();
        Contact c = makeContact(true);

        Test.startTest();
        new RSAMaskBatch('Contact', new List<Id>{c.Id}, fields(), LOG_FIELD, FLAG_FIELD)
            .execute(null, new List<Id>{c.Id});
        Test.stopTest();

        Contact after = [SELECT LastName, Email FROM Contact WHERE Id = :c.Id];
        System.assertEquals('Smith', after.LastName);
        System.assertEquals('john@example.com', after.Email);
    }

    @IsTest
    static void flagsRecordWhenNothingToEncrypt() {
        useValidKey();
        Contact c = new Contact(LastName = 'Smith');   // Email is blank, so no log lines
        insert c;

        Test.startTest();
        new RSAMaskBatch('Contact', new List<Id>{c.Id}, new List<String>{'Email'}, LOG_FIELD, FLAG_FIELD)
            .execute(null, new List<Id>{c.Id});
        Test.stopTest();

        Contact after = [SELECT LastName, HasOptedOutOfEmail, Description FROM Contact WHERE Id = :c.Id];
        System.assertEquals('Smith', after.LastName);
        System.assertEquals(true, after.HasOptedOutOfEmail);
        System.assertEquals(null, after.Description);
    }

    @IsTest
    static void toleratesNullFieldList() {
        useValidKey();
        Contact c = new Contact(LastName = 'Smith');
        insert c;

        new RSAMaskBatch('Contact', new List<Id>{c.Id}, null, LOG_FIELD, FLAG_FIELD)
            .execute(null, new List<Id>{c.Id});

        System.assertEquals(true, [SELECT HasOptedOutOfEmail FROM Contact WHERE Id = :c.Id].HasOptedOutOfEmail);
    }

    @IsTest
    static void failsWhenKeyMissingOrInvalid() {
        Contact c = makeContact(false);
        List<Id> scope = new List<Id>{c.Id};
        RSAMaskBatch b = new RSAMaskBatch('Contact', scope, fields(), LOG_FIELD, FLAG_FIELD);
        Integer thrown = 0;

        RSAMaskBatch.testConfigs = new List<RSA_Key_Config__mdt>();
        try { b.execute(null, scope); } catch (RSAMaskBatch.RSAMaskException e) { thrown++; }

        RSAMaskBatch.testConfigs = new List<RSA_Key_Config__mdt>{
            new RSA_Key_Config__mdt(DeveloperName = 'Default_Key', Modulus__c = '', Exponent__c = '10001')};
        try { b.execute(null, scope); } catch (RSAMaskBatch.RSAMaskException e) { thrown++; }

        RSAMaskBatch.testConfigs = new List<RSA_Key_Config__mdt>{
            new RSA_Key_Config__mdt(DeveloperName = 'Default_Key', Modulus__c = 'f'.repeat(512), Exponent__c = '')};
        try { b.execute(null, scope); } catch (RSAMaskBatch.RSAMaskException e) { thrown++; }

        RSAMaskBatch.testConfigs = new List<RSA_Key_Config__mdt>{
            new RSA_Key_Config__mdt(DeveloperName = 'Default_Key', Modulus__c = 'abc', Exponent__c = '10001')};
        try { b.execute(null, scope); } catch (RSAMaskBatch.RSAMaskException e) { thrown++; }

        System.assertEquals(4, thrown);
    }

    @IsTest
    static void placeholdersMatchFieldTypes() {
        System.assertEquals('*****', RSAMaskBatch.requiredPlaceholder(Schema.Contact.LastName.getDescribe()));
        System.assertEquals('*****', RSAMaskBatch.requiredPlaceholder(Schema.Contact.Phone.getDescribe()));
        System.assertEquals('*****', RSAMaskBatch.requiredPlaceholder(Schema.Contact.Description.getDescribe()));
        System.assertEquals('masked@masked.invalid', RSAMaskBatch.requiredPlaceholder(Schema.Contact.Email.getDescribe()));
        System.assertEquals('https://masked.invalid', RSAMaskBatch.requiredPlaceholder(Schema.Account.Website.getDescribe()));
        System.assertEquals(false, RSAMaskBatch.requiredPlaceholder(Schema.Contact.DoNotCall.getDescribe()));
        System.assertEquals(0, RSAMaskBatch.requiredPlaceholder(Schema.Account.NumberOfEmployees.getDescribe()));
        System.assertEquals(Decimal.valueOf(0), RSAMaskBatch.requiredPlaceholder(Schema.Opportunity.Amount.getDescribe()));
        System.assertEquals(Decimal.valueOf(0), RSAMaskBatch.requiredPlaceholder(Schema.Opportunity.Probability.getDescribe()));
        System.assertEquals(Date.newInstance(1900, 1, 1), RSAMaskBatch.requiredPlaceholder(Schema.Contact.Birthdate.getDescribe()));
        System.assertNotEquals(null, RSAMaskBatch.requiredPlaceholder(Schema.Contact.CreatedDate.getDescribe()));
        System.assertEquals(Time.newInstance(0, 0, 0, 0), RSAMaskBatch.requiredPlaceholder(Schema.BusinessHours.MondayStartTime.getDescribe()));
        System.assertEquals(null, RSAMaskBatch.requiredPlaceholder(Schema.Contact.LeadSource.getDescribe()), 'Picklists have no safe placeholder');
        System.assertEquals(null, RSAMaskBatch.requiredPlaceholder(Schema.Contact.ReportsToId.getDescribe()), 'Lookups have no safe placeholder');
    }
}
