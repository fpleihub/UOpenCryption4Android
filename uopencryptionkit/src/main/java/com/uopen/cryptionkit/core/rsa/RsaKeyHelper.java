package com.uopen.cryptionkit.core.rsa;
/**
 * Created by fplei on 2018/9/25.
 */

import android.text.TextUtils;
import android.util.Log;

import com.uopen.cryptionkit.utils.UUIDUtils;
import com.uopen.cryptionkit.utils.Utils;
import org.bouncycastle.util.encoders.Base64;
import java.io.File;
import java.io.FileWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * author:fplei
 * date:2018/9/25
 * des:
 **/
public class RsaKeyHelper {
    /** 密钥对生成器 */
    private static KeyPairGenerator keyPairGenerator = null;

    private static KeyFactory keyFactory = null;
    /** 缓存的密钥对 */
    private static KeyPair keyPair = null;
    private static final String ALGORITHM =  "RSA";
    /** 默认密钥大小 */
    private static final int KEY_SIZE = 1024;
    /** 初始化密钥工厂 */
    static{
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyFactory = KeyFactory.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * 构造RSA公钥
     * @param keyBytes 密钥数组
     * @return
     */
    public static RSAPublicKey getPublicKey(byte[] keyBytes){
        if(keyBytes==null){
            return null;
        }
        try {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            return (RSAPublicKey)keyFactory.generatePublic(x509EncodedKeySpec);
        }catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 构造RSA私钥（RSAPrivateKey）
     * @param privateKey 密钥数组
     * @return
     */
    public static RSAPrivateKey getPrivateKey(byte[] privateKey){
        try {
            if(privateKey==null){
                return null;
            }
            Log.i("lfp","privateKey.size="+privateKey.length);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
            return (RSAPrivateKey)keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 生成密钥对
     * 将密钥分别用Base64编码保存到#publicKey.properties#和#privateKey.properties#文件中
     * 保存的默认名称分别为publicKey和privateKey
     */
    public static synchronized KeyPass generateKeyPair(){
        try {
            keyPairGenerator.initialize(KEY_SIZE,new SecureRandom(UUIDUtils.getUUID().getBytes()));
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e){
            e.printStackTrace();
        }
        RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
        //生成的密钥对编码成base64
        String publicKeyString = Utils.byteToHex(rsaPublicKey.getEncoded());
        String privateKeyString = Utils.byteToHex(rsaPrivateKey.getEncoded());
        KeyPass keyPass=new KeyPass();
        keyPass.setPublicKeyHex(publicKeyString);
        keyPass.setPrivateKeyHex(privateKeyString);
        return keyPass;
    }

    public static class KeyPass{
        private String publicKeyHex;
        private  String privateKeyHex;

        public String getPublicKeyHex() {
            return publicKeyHex;
        }

        public void setPublicKeyHex(String publicKeyHex) {
            this.publicKeyHex = publicKeyHex;
        }

        public String getPrivateKeyHex() {
            return privateKeyHex;
        }

        public void setPrivateKeyHex(String privateKeyHex) {
            this.privateKeyHex = privateKeyHex;
        }

        /**
         * 保存到文件16进制
         * @param privateKeyFilePath 私钥保存文件路径
         * @param publicKeyFilePath 公密钥保存文件地址
         */
        public void saveToFile(String privateKeyFilePath,String publicKeyFilePath)throws Exception{
            if(TextUtils.isEmpty(privateKeyFilePath)||TextUtils.isEmpty(publicKeyFilePath)
                    ||publicKeyHex==null||privateKeyHex==null){
                throw new Exception("error:saveToFile function args invalid ?");
            }
            File privateKeyFile=new File(privateKeyFilePath);
            File publicKeyFile=new File(publicKeyFilePath);
            try{
                privateKeyFile.createNewFile();
                publicKeyFile.createNewFile();
            }catch (Exception e){
                e.printStackTrace();
            }
            FileWriter fileWriterPrivate=new FileWriter(privateKeyFile);
            fileWriterPrivate.write(privateKeyHex);
            fileWriterPrivate.flush();
            fileWriterPrivate.close();

            FileWriter fileWriterPublic=new FileWriter(publicKeyFile);
            fileWriterPublic.write(publicKeyHex);
            fileWriterPublic.flush();
            fileWriterPublic.close();
        }
    }
}
