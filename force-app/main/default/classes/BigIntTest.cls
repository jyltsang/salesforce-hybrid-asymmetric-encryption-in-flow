@IsTest
private class BigIntTest {

    @IsTest
    static void roundTripsHex() {
        System.assertEquals('ff', new BigInt('FF', 16).toHex());
        System.assertEquals('ff', new BigInt('0x00ff', 16).toHex());
        System.assertEquals('0', new BigInt('0', 16).toHex());
        // Multi-chunk values, including lengths that are not a multiple of 8
        System.assertEquals('123456789', new BigInt('123456789', 16).toHex());
        System.assertEquals('ffffffffffffffff', new BigInt('ffffffffffffffff', 16).toHex());
        System.assertEquals('abcdef0123456789abc', new BigInt('abcdef0123456789abc', 16).toHex());
    }

    @IsTest
    static void modPowKnownValues() {
        // 4^13 mod 497 = 445 (0x1bd)
        System.assertEquals('1bd',
            new BigInt('4', 16).modPow(new BigInt('d', 16), new BigInt('1f1', 16)).toHex());
        // x^0 mod n = 1
        System.assertEquals('1',
            new BigInt('abc', 16).modPow(new BigInt('0', 16), new BigInt('1f1', 16)).toHex());
        // 2^10 mod 1000 = 24 (0x18)
        System.assertEquals('18',
            new BigInt('2', 16).modPow(new BigInt('a', 16), new BigInt('3e8', 16)).toHex());
    }

    @IsTest
    static void textbookRsaRoundTrip() {
        BigInt n = new BigInt('ca1', 16);                                       // 3233 = 61 * 53
        BigInt cipher = new BigInt('41', 16).modPow(new BigInt('11', 16), n);   // 65^17
        System.assertEquals('ae6', cipher.toHex());                             // 2790
        BigInt plain = cipher.modPow(new BigInt('ac1', 16), n);                 // ^2753
        System.assertEquals('41', plain.toHex());                               // 65
    }

    @IsTest
    static void modPowWithModulusBeyond64Bits() {
        // 2^89 - 1 is a Mersenne number, so 2^100 mod (2^89 - 1) = 2^11 = 2048 (0x800)
        BigInt mersenne = new BigInt('1' + 'f'.repeat(22), 16);
        System.assertEquals('800',
            new BigInt('2', 16).modPow(new BigInt('64', 16), mersenne).toHex());
    }

    @IsTest
    static void rejectsInvalidInput() {
        Integer thrown = 0;
        try { new BigInt('ff', 10); } catch (BigInt.BigIntException e) { thrown++; }
        try { new BigInt(null, 16); } catch (BigInt.BigIntException e) { thrown++; }
        try { new BigInt('   ', 16); } catch (BigInt.BigIntException e) { thrown++; }
        try { new BigInt('xyz', 16); } catch (BigInt.BigIntException e) { thrown++; }
        try {
            new BigInt('5', 16).modPow(new BigInt('3', 16), new BigInt('1', 16));
        } catch (BigInt.BigIntException e) { thrown++; }
        System.assertEquals(5, thrown, 'Each invalid input should raise BigIntException');
    }
}
