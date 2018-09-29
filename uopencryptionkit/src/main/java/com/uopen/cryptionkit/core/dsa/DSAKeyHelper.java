package com.uopen.cryptionkit.core.dsa;

import android.text.TextUtils;

import com.uopen.cryptionkit.utils.Utils;

import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Created by fplei on 2018/9/26.
 */
public class DSAKeyHelper {
    public static final String KEY_ALGORITHM = "DSA";
    public static final int KEY_SIZE=1024;
    public static class KeyPass{
        //16位编码公钥
        private String publicKeyHex;
        //16位编码私钥
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

        //密钥保存到文件
        public void saveToFile(String privateKeyFilePath,String publicKeyFilePath)throws Exception{
            if(TextUtils.isEmpty(privateKeyFilePath)||TextUtils.isEmpty(publicKeyFilePath)
                    ||TextUtils.isEmpty(this.privateKeyHex)||TextUtils.isEmpty(this.publicKeyHex)){
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
            fileWriterPrivate.write(this.privateKeyHex);
            fileWriterPrivate.flush();
            fileWriterPrivate.close();

            FileWriter fileWriterPublic=new FileWriter(publicKeyFile);
            fileWriterPublic.write(this.publicKeyHex);
            fileWriterPublic.flush();
            fileWriterPublic.close();
        }
    }

    public static KeyPass genKeyPair(String seed){
        try{
            KeyPairGenerator keygen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.setSeed(seed.getBytes());
            //Modulus size must range from 512 to 1024 and be a multiple of 64
            keygen.initialize(KEY_SIZE, secureRandom);
            keygen.genKeyPair();
            KeyPair keys = keygen.genKeyPair();
            PrivateKey privateKey = keys.getPrivate();
            PublicKey publicKey = keys.getPublic();
            KeyPass keyPass=new KeyPass();
            keyPass.setPublicKeyHex(Utils.byteToHex(publicKey.getEncoded()));
            keyPass.setPrivateKeyHex(Utils.byteToHex(privateKey.getEncoded()));
            return keyPass;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
}
