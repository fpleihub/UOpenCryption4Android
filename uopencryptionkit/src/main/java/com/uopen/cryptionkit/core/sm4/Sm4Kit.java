package com.uopen.cryptionkit.core.sm4;

import android.text.TextUtils;
import android.util.Base64;

import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.utils.Utils;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by fplei on 2018/9/21.
 */

public class Sm4Kit extends AbstractCoder{
//    public String iv = "";
//    public boolean hexString = false;
    /*public String encryptData_ECB(String plainText)
    {
        try
        {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            if (hexString)
            {
                keyBytes = Utils.hexStringToBytes(secretKey);
            }
            else
            {
                keyBytes = secretKey.getBytes();
            }
            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes("UTF-8"));
            String cipherText = Base64.encodeToString(encrypted,Base64.NO_WRAP);
            if (cipherText != null && cipherText.trim().length() > 0)
            {
                Pattern p = Pattern.compile("\\s*|\t|\r|\n");
                Matcher m = p.matcher(cipherText);
                cipherText = m.replaceAll("");
            }
            return cipherText;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    public String decryptData_ECB(String cipherText)
    {
        try
        {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;
            byte[] keyBytes;
            if (hexString)
            {
                keyBytes = Utils.hexStringToBytes(secretKey);
            }
            else
            {
                keyBytes = secretKey.getBytes();
            }

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            byte[] decrypted = sm4.sm4_crypt_ecb(ctx, Base64.decode(cipherText,Base64.NO_WRAP));
            return new String(decrypted, "UTF-8");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }*/

    @Override
    public String simpleEnCode(String value, String key) {
        if(TextUtils.isEmpty(value)||TextUtils.isEmpty(key)){
            return null;
        }
        try{
            byte[] keyBytes= Utils.hexStringToBytes(key);
            byte[] result=enCode(value.getBytes("utf-8"),keyBytes);
            if(result==null){
                return null;
            }
            return Utils.byteToHex(result);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] enCode(byte[] value, byte[] key) {
        if(value==null||key==null){
            return null;
        }
        try{
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;
            byte[] keyBytes= key;
            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_ecb(ctx, value);
            return encrypted;
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
        try{
            byte[] keyBytes=Utils.hexStringToBytes(key);
            byte[] ciphers=Utils.hexStringToBytes(value);
            byte[] result=deCode(ciphers,keyBytes);
            if(result==null){
                return null;
            }
            return new String(result, "UTF-8");
        }catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] deCode(byte[] value, byte[] key) {
        if(value==null||key==null){
            return null;
        }
        try
        {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;
            byte[] keyBytes=key;
            byte[] ciphers=value;
            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            return sm4.sm4_crypt_ecb(ctx, ciphers);
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    /*public String encryptData_CBC(String plainText)
    {
        try
        {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
            if (hexString)
            {
                keyBytes = Utils.hexStringToBytes(secretKey);
                ivBytes = Utils.hexStringToBytes(iv);
            }
            else
            {
                keyBytes = secretKey.getBytes();
                ivBytes = iv.getBytes();
            }
            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText.getBytes("UTF-8"));
            String cipherText =Base64.encodeToString(encrypted,Base64.NO_WRAP);
            if (cipherText != null && cipherText.trim().length() > 0)
            {
                Pattern p = Pattern.compile("\\s*|\t|\r|\n");
                Matcher m = p.matcher(cipherText);
                cipherText = m.replaceAll("");
            }
            return cipherText;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    public String decryptData_CBC(String cipherText)
    {
        try
        {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
            if (hexString)
            {
                keyBytes = Utils.hexStringToBytes(secretKey);
                ivBytes = Utils.hexStringToBytes(iv);
            }
            else
            {
                keyBytes = secretKey.getBytes();
                ivBytes = iv.getBytes();
            }
            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes,Base64.decode(cipherText,Base64.NO_WRAP));
            return new String(decrypted, "UTF-8");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }*/
}
