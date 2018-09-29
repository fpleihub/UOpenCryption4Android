package com.uopen.cryptionkit.core.aes;

import java.security.Provider;

/**
 * Created by fplei on 2018/9/25.
 */

public class CryptoProvider extends Provider{
    public CryptoProvider() {
        super("Crypto", 1.0, "HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature)");
        put("SecureRandom.SHA1PRNG","org.apache.harmony.security.provider.crypto.SHA1PRNG_SecureRandomImpl");
        put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
    }

}
