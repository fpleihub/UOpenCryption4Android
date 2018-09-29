package com.uopen.cryptionkit.core.des;

import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.utils.StringUtils;
import com.uopen.cryptionkit.utils.Utils;
import org.bouncycastle.util.encoders.Base64;
import java.io.UnsupportedEncodingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by fplei on 2018/9/25.
 * author:fplei
 * date:2018/9/25
 * des: 3DES加解密
 **/
public class TriDesKit extends AbstractCoder {
    //定义加密算法，有DES、DESede(即3DES)、Blowfish
    private static final String Algorithm = "DESede";

    @Override
    public String simpleEnCode(String value, String key) {
        try{
            if(StringUtils.isNull(key)||StringUtils.isNull(value)){
                return null;
            }
            byte [] byte_encode=enCode(value.getBytes("utf-8"),key.getBytes());
            if(byte_encode!=null){
                return Utils.byteToHex(byte_encode);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] enCode(byte[] value, byte[] key) {
        try {
            if(key==null||value==null){
                return null;
            }
            SecretKey deskey = new SecretKeySpec(build3DesKey(key), Algorithm);    //生成密钥
            Cipher c1 = Cipher.getInstance(Algorithm);    //实例化负责加密/解密的Cipher工具类
            c1.init(Cipher.ENCRYPT_MODE, deskey);    //初始化为加密模式
            return c1.doFinal(value);
        } catch (Exception e1) {
            e1.printStackTrace();
        }
        return null;
    }
    @Override
    public String simpleDeCode(String value, String key) {
        try{
            if(StringUtils.isNull(key)||StringUtils.isNull(value)){
                return null;
            }
            byte[] values=Utils.hexStringToBytes(value);;
            return  new String(deCode(values,key.getBytes()),"utf-8");
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }


    @Override
    public byte[] deCode(byte[] value, byte[] key) {
        try {
            if(key==null||value==null){
                return null;
            }
            SecretKey deskey = new SecretKeySpec(build3DesKey(key), Algorithm);
            Cipher c1 = Cipher.getInstance(Algorithm);
            c1.init(Cipher.DECRYPT_MODE, deskey);    //初始化为解密模式
            return c1.doFinal(value);
        } catch (Exception e1) {
            e1.printStackTrace();
        }
        return null;
    }

    /*
     * 根据字符串生成密钥字节数组
     * @param keyStr 密钥字符串
     * @return
     * @throws UnsupportedEncodingException
     */
    private static byte[] build3DesKey(byte[] keyStr) throws UnsupportedEncodingException {
        byte[] key = new byte[24];    //声明一个24位的字节数组，默认里面都是0
        byte[] temp = keyStr;    //将字符串转成字节数组
        /*
         * 执行数组拷贝
         * System.arraycopy(源数组，从源数组哪里开始拷贝，目标数组，拷贝多少位)
         */
        if (temp.length<=key.length ) {
            //如果temp不够24位，则拷贝temp数组整个长度的内容到key数组中
            System.arraycopy(temp, 0, key, 0, temp.length);
        } else {
            //如果temp大于24位，则拷贝temp数组24个长度的内容到key数组中
            System.arraycopy(temp, 0, key, 0, key.length);
        }
        return key;
    }
}
