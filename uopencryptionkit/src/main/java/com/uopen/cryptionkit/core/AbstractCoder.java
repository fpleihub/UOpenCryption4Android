package com.uopen.cryptionkit.core;
/**
 * Created by fplei on 2018/9/25.
 */

import android.util.Log;

import com.uopen.cryptionkit.utils.Utils;

import org.bouncycastle.util.encoders.Base64;

/**
 * author:fplei
 * date:2018/9/25
 * des:/
 **/
public abstract class AbstractCoder{
    /**
     * 加密
     * @param value 需要加密的数据
     * @param key  密钥
     * @return 该方法返回默认16进制编码字符串
     */
    public abstract String simpleEnCode(String value,String key);

    /**
     * 加密，返回原始byte[]数组
     * @param value 需要加密的数据byte[]
     * @param key 密钥byte[]
     * @return 该方法返回原始byte[]
     */
    public abstract byte[] enCode(byte[] value,byte[] key);
    /**
     * 解密数据
     * @param value 需要解密数据(默认传入为16进制数据)
     * @param key 密钥
     * @return
     */
    public abstract String simpleDeCode(String value,String key);

    /**
     * 解密（传入数据为byte），返回byte[]
     * @param value 需要解密数据byte[]
     * @param key 密钥byte[]
     * @return
     */
    public abstract byte[] deCode(byte[] value,byte[] key);

    /**
     * 计算data串签名
     * @param data 数据串
     * @param key 参加计算签名的密钥（默认使用16进制编码，不使用请直接传入byte数组），不需要串null（MD5/SM3不需要，SHA1/DSA才需要）
     * @return 默认返回16进制字符串
     */
    public String digestSignature(String data,String key){
        return null;
    }

    /**
     * 计算data串签名
     * @param data 数据原始byte数组
     * @param key 参加签名密钥byte数组
     * @return 返回原始byte数组
     */
    public byte[] digestSignature(byte[] data,byte[] key){
        return null;
    }
    /**
     * 验证签名数据是否正确
     * @param data       需要验证的数据
     * @param signature 经过私钥计算出的签名
     * @param publicKey 公钥
     * @return
     */
    public boolean verifyWithDSA(byte[] data, String signature,byte[] publicKey){
        return false;
    }


}
