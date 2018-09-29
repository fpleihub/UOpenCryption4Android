package com.uopen.cryptionkit.core.sha1;

import android.text.TextUtils;
import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.utils.Utils;
import org.bouncycastle.util.encoders.Base64;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by fplei on 2018/9/26.
 * HmacSHA1签名算法
 */
public class HMacSha1Kit extends AbstractCoder{
    private static final String Algorithm="HmacSHA1";

    @Override
    public String simpleEnCode(String value, String key) {return null;}
    @Override
    public byte[] enCode(byte[] value, byte[] key) {return null;}
    @Override
    public String simpleDeCode(String value, String key) {
        return null;
    }
    @Override
    public byte[] deCode(byte[] value, byte[] key) {
        return null;
    }

    @Override
    public String digestSignature(String data, String key) {
        if(TextUtils.isEmpty(data)||TextUtils.isEmpty(key)){
            return null;
        }
        try {
            byte[] keyBytes=key.getBytes();
            byte[] result=digestSignature(data.getBytes("utf-8"),keyBytes);
            if(result!=null){
                return Utils.byteToHex(result);
            }
        }catch (Exception e){

        }
        return null;
    }

    @Override
    public byte[] digestSignature(byte[] data, byte[] key) {
        if(data==null||key==null){
            return null;
        }
        try {
            SecretKey signingKey = new SecretKeySpec(key, Algorithm);
            Mac mac = Mac.getInstance(Algorithm);
            mac.init(signingKey);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }
}
