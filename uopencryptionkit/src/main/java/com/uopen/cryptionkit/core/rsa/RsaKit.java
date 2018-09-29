package com.uopen.cryptionkit.core.rsa;

import android.text.TextUtils;
import android.util.Log;

import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.utils.Utils;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;

/**
 * Created by fplei on 2018/9/25.
 * author:fplei
 * date:2018/9/25
 * des:RSA加解密（公钥加密，私钥解密）
 **/
public class RsaKit extends AbstractCoder {
    public static final String ALGORITHM = "RSA";

    /**
     *
     * @param value 需要加密的数据
     * @param key  密钥 16进制字符串
     * @return
     */
    @Override
    public String simpleEnCode(String value, String key) {
        if(TextUtils.isEmpty(value)||TextUtils.isEmpty(key)){
            return null;
        }
        try{
            byte[] keyBytes=Utils.hexStringToBytes(key);
            byte[] result=enCode(value.getBytes("utf-8"),keyBytes);
            return  result!=null?Utils.byteToHex(result):null;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] enCode(byte[] value, byte[] key) {
        Log.i("lfp","key.size="+key.length);
        RSAPublicKey publicKey= RsaKeyHelper.getPublicKey(key);
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            //该密钥能够加密的最大字节长度
            int splitLength = ((RSAPublicKey)publicKey).getModulus().bitLength() / 8 -11;
            byte[][] arrays = splitBytes(value,splitLength);
            ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
            for (byte[] array : arrays){
                byte[] temp=cipher.doFinal(array);
                byteArrayOutputStream.write(temp,byteArrayOutputStream.size(),temp.length);
            }
            byteArrayOutputStream.close();
            return byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    /**
     * 解密
     * @param value 需要解密数据(默认传入为16进制数据)
     * @param key 密钥 传入16进制字符串
     * @return
     */
    @Override
    public String simpleDeCode(String value, String key) {
        if(TextUtils.isEmpty(value)||TextUtils.isEmpty(key)){
            return null;
        }
        try {
            byte[] datas = Utils.hexStringToBytes(value);
            byte[] keyBytes=Utils.hexStringToBytes(key);
            byte[] result=deCode(datas,keyBytes);
            return result!=null?new String(result):null;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] deCode(byte[] value, byte[] key) {
        if(value==null|| key==null){
            return null;
        }
        try{
            RSAPrivateKey privateKey=RsaKeyHelper.getPrivateKey(key);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            //该密钥能够加密的最大字节长度
            int splitLength = ((RSAPrivateKey)privateKey).getModulus().bitLength() / 8;
            byte[] contentBytes = value;
            byte[][] arrays = splitBytes(contentBytes,splitLength);
            ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
            ByteBuffer byteBuffer=ByteBuffer.allocate(contentBytes.length);
            for (byte[] array : arrays){
                byte[] temp=cipher.doFinal(array);
                byteBuffer.put(temp);
//                byteArrayOutputStream.write(temp,byteArrayOutputStream.size(),temp.length);
            }
            byteArrayOutputStream.flush();
            byteArrayOutputStream.close();
            return byteBuffer.array();
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 根据限定的每组字节长度，将字节数组分组
     * @param bytes 等待分组的字节组
     * @param splitLength 每组长度
     * @return 分组后的字节组
     */
    public byte[][] splitBytes(byte[] bytes,int splitLength){
        //bytes与splitLength的余数
        int remainder = bytes.length % splitLength;
        //数据拆分后的组数，余数不为0时加1
        int quotient = remainder != 0 ? bytes.length / splitLength + 1:bytes.length / splitLength;
        byte[][] arrays = new byte[quotient][];
        byte[] array = null;
        for (int i =0;i<quotient;i++){
            //如果是最后一组（quotient-1）,同时余数不等于0，就将最后一组设置为remainder的长度
            if (i == quotient -1 && remainder != 0){
                array = new byte[remainder];
                System.arraycopy(bytes,i * splitLength,array,0,remainder);
            } else {
                array = new byte[splitLength];
                System.arraycopy(bytes,i*splitLength,array,0,splitLength);
            }
            arrays[i] = array;
        }
        return arrays;
    }
}
