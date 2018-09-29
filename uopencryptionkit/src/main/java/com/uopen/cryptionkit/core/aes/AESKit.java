package com.uopen.cryptionkit.core.aes;


import android.text.TextUtils;

import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.utils.Utils;
import org.bouncycastle.util.encoders.Base64;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * author:fplei
 * date:2018-09-25
 * des:
 **/
public class AESKit extends AbstractCoder{
    private static final String TAG=AESKit.class.getSimpleName();
    private static final String Algorithm="AES";
    private static final String AlgorithmPadding="AES/ECB/PKCS5Padding";
    /*
         * 加密
         * 1.构造密钥生成器
         * 2.根据ecnodeRules规则初始化密钥生成器
         * 3.产生密钥
         * 4.创建和初始化密码器
         * 5.内容加密
         * 6.返回字符串
        */
    @Override
    public String simpleEnCode(String value, String key) {
        if(TextUtils.isEmpty(key)||TextUtils.isEmpty(value)){
            return null;
        }
        try {
            byte [] byte_AES=enCode(value.getBytes("utf-8"),key.getBytes());
            if(byte_AES!=null){
                return Utils.byteToHex(byte_AES);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        //如果有错就返加null
        return null;
    }
    @Override
    public byte[] enCode(byte[] value, byte[] key) {
        if(key==null||value==null){
            return null;
        }
        try {
            SecretKey _key=new SecretKeySpec(getRawKey(key), Algorithm);
            Cipher cipher=Cipher.getInstance(AlgorithmPadding);
            cipher.init(Cipher.ENCRYPT_MODE, _key);
            return cipher.doFinal(value);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    /*
    * 解密
    * 解密过程：
    * 1.同加密1-4步
    * 2.将加密后的字符串反纺成byte[]数组
    * 3.将加密内容解密
    */
    @Override
    public String simpleDeCode(String value, String key) {
        if(TextUtils.isEmpty(key)||TextUtils.isEmpty(value)){
            return null;
        }
        try {
            byte[] values=Utils.hexStringToBytes(value);;
            byte [] byte_decode=deCode(values,key.getBytes());
            return new String(byte_decode,"utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }



    @Override
    public byte[] deCode(byte[] value, byte[] key) {
        if(key==null||value==null){
            return null;
        }
        try {
            SecretKey _key=new SecretKeySpec(getRawKey(key), Algorithm);
            Cipher cipher=Cipher.getInstance(AlgorithmPadding);
            cipher.init(Cipher.DECRYPT_MODE, _key);
            byte [] byte_decode=cipher.doFinal(value);
            return byte_decode;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 生成key
     * @param seed
     * @return
     * @throws Exception
     */
    private static byte[] getRawKey(byte[] seed) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance(Algorithm);
        SecureRandom sr=SecureRandom.getInstance("SHA1PRNG", new CryptoProvider());;
        sr.setSeed(seed);
        kgen.init(128, sr);
        SecretKey skey = kgen.generateKey();
        byte[] raw = skey.getEncoded();
        return raw;
    }

}
