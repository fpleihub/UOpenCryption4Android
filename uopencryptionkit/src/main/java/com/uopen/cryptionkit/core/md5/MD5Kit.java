package com.uopen.cryptionkit.core.md5;

import android.text.TextUtils;

import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.utils.Utils;

import org.bouncycastle.util.encoders.Base64;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by fplei on 2018/9/26.
 * 计算MD5摘要，enCode函数生效，deCode函数不实现
 */
public class MD5Kit extends AbstractCoder {
    private static final String Algorithm="MD5";
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
        if(TextUtils.isEmpty(data)){
            return null;
        }
        try{
            byte[] result=digestSignature(data.getBytes("utf-8"),null);
            if(result!=null){
                return Utils.byteToHex(result);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] digestSignature(byte[] data, byte[] key) {
        if(data==null){
            return null;
        }
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance(Algorithm);
            byte[] bytes = md5.digest(data);
            return bytes;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
