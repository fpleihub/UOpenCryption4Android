package com.uopen.cryptionkit.core.sm2;
/**
 * Created by fplei on 2018/9/25.
 */

import com.uopen.cryptionkit.utils.Utils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * author:fplei
 * date:2018/9/25
 * des:
 **/
public class SM2KeyHelper {

    //生成随机秘钥对
    public static KeyPair generateKeyPair(Sm2Kit sm2Kit){
        if(sm2Kit==null){
            return null;
        }
        AsymmetricCipherKeyPair key = sm2Kit.ecc_key_pair_generator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
        BigInteger privateKey = ecpriv.getD();
        ECPoint publicKey = ecpub.getQ();
        KeyPair keyPair=new KeyPair();
        keyPair.setPublicKey(Utils.byteToHex(publicKey.getEncoded()));
        keyPair.setPrivateKey(Utils.byteToHex(privateKey.toByteArray()));
        return keyPair;
    }

    public static class KeyPair{
        private String publicKey;
        private String privateKey;

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }
    }
}
