package com.uopen.cryptionkit.core.dsa;

import android.text.TextUtils;
import android.util.Log;

import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.utils.Utils;
import org.bouncycastle.util.encoders.Base64;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by fplei on 2018/9/26.
 * DSA-Digital Signature Algorithm 是Schnorr和ElGamal签名算法的变种，被美国NIST作为DSS(DigitalSignature Standard)。
 * 简单的说，这是一种更高级的验证方式，用作数字签名。不单单只有公钥、私钥，还有数字签名。私钥加密生成数字签名，公钥验证数据及签名。
 * 如果数据和签名不匹配则认为验证失败！即 传输中的数据 可以不再加密，接收方获得数据后，拿到公钥与签名 验证数据是否有效
 */
public class DSAKit extends AbstractCoder{
    public static final String KEY_ALGORITHM = "DSA";
    public static final String SIGNATURE_ALGORITHM = "DSA";
    public static final String DEFAULT_SEED = "$%^*%^()(HJG8awfjas7"; //默认种子

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

    /**
     * 签名计算
     * @param data 数据串
     * @param key 参加计算签名的密钥（默认使用16进制编码，不使用请直接传入byte数组），不需要串null（MD5/SM3不需要，SHA1/DSA才需要）
     * @return
     */
    @Override
    public String digestSignature(String data, String key) {
        if(TextUtils.isEmpty(data)||TextUtils.isEmpty(key)){
            return null;
        }
        byte[] keyBytes=Utils.hexStringToBytes(key);
        byte[] result=digestSignature(data.getBytes(),keyBytes);
        if(result==null){
            return null;
        }
        return Utils.byteToHex(result);
    }

    @Override
    public byte[] digestSignature(byte[] data, byte[] key) {
        if(data==null|| key==null){
            return null;
        }
        try{
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
            PrivateKey priKey = factory.generatePrivate(keySpec);//生成 私钥
            // 用私钥对信息进行数字签名
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(priKey);
            signature.update(data);
            return signature.sign();
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 验证签名数据
     * @param data       需要验证的数据
     * @param sign       计算的签名
     * @param publicKey 公钥
     * @return
     */
    @Override
    public boolean verifyWithDSA(byte[] data, String sign, byte[] publicKey) {
        if(data==null||publicKey==null||TextUtils.isEmpty(sign)){
            return false;
        }
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(pubKey);
            signature.update(data);
            byte[] signBytes=null;
            if(Utils.isHexNumber(sign)){
                signBytes=Utils.hexStringToBytes(sign);
            }else {
                signBytes=sign.getBytes();
            }
            return signature.verify(signBytes); //验证签名
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

}
