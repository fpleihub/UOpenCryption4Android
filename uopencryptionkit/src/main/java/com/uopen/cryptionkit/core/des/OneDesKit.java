package com.uopen.cryptionkit.core.des;

import android.text.TextUtils;

import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.utils.Utils;

import org.bouncycastle.util.encoders.Base64;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Created by fplei on 2018/9/26.
 */

public class OneDesKit extends AbstractCoder {
    private static final String ALGORITHM_DES = "DES/CBC/PKCS5Padding";
    private static final String Algorithm = "DES";
    private static final String IV="12345678";

    @Override
    public String simpleEnCode(String value, String key) {
        if(TextUtils.isEmpty(value)||TextUtils.isEmpty(key)){
            return null;
        }
        byte[] bytes=enCode(value.getBytes(),key.getBytes());
        if(bytes==null){
            return null;
        }
        return Utils.byteToHex(bytes);
    }

    @Override
    public byte[] enCode(byte[] value, byte[] key) {
        if(value==null||key==null){
            return null;
        }
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(Algorithm);
            DESKeySpec dks = new DESKeySpec(key);
            // key的长度不能够小于8位字节
            Key secretKey = keyFactory.generateSecret(dks);
            Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
            IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
            AlgorithmParameterSpec paramSpec = iv;
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            return cipher.doFinal(value);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String simpleDeCode(String value, String key) {
        if(TextUtils.isEmpty(value)||TextUtils.isEmpty(key)){
            return null;
        }
        byte[] datas=Utils.hexStringToBytes(value);;
        byte[] result=deCode(datas,key.getBytes());
        if(result==null){
            return null;
        }
        return new String(result);
    }

    @Override
    public byte[] deCode(byte[] value, byte[] key) {
        if(value==null||key==null){
            return null;
        }
        try{
            DESKeySpec dks = new DESKeySpec(key);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(Algorithm);
            // key的长度不能够小于8位字节
            Key secretKey = keyFactory.generateSecret(dks);
            Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
            IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
            AlgorithmParameterSpec paramSpec = iv;
            cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
            return cipher.doFinal(value);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
}
