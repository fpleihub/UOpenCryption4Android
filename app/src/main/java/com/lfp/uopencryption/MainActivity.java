package com.lfp.uopencryption;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import com.uopen.cryptionkit.EncryptionManager;
import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.core.dsa.DSAKeyHelper;
import com.uopen.cryptionkit.core.rsa.RsaKeyHelper;
import com.uopen.cryptionkit.core.sm2.SM2KeyHelper;
import com.uopen.cryptionkit.core.sm2.Sm2Kit;
import com.uopen.cryptionkit.utils.Utils;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    private EditText et_encryption;
    private TextView text_result;
    private Button bt_sm2,bt_sm3,bt_sm4,bt_trides,bt_onedes,bt_aes,bt_dsa,bt_rsa,bt_sha1,bt_md5;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        et_encryption=findViewById(R.id.et_encryption);
        text_result=findViewById(R.id.text_result);
        bt_sm2=findViewById(R.id.bt_sm2);
        bt_sm2.setOnClickListener(this);
        bt_sm3=findViewById(R.id.bt_sm3);
        bt_sm3.setOnClickListener(this);
        bt_sm4=findViewById(R.id.bt_sm4);
        bt_sm4.setOnClickListener(this);
        bt_trides=findViewById(R.id.bt_trides);
        bt_trides.setOnClickListener(this);
        bt_onedes=findViewById(R.id.bt_onedes);
        bt_onedes.setOnClickListener(this);
        bt_aes=findViewById(R.id.bt_aes);
        bt_aes.setOnClickListener(this);
        bt_dsa=findViewById(R.id.bt_dsa);
        bt_dsa.setOnClickListener(this);
        bt_rsa=findViewById(R.id.bt_rsa);
        bt_rsa.setOnClickListener(this);
        bt_sha1=findViewById(R.id.bt_sha1);
        bt_sha1.setOnClickListener(this);
        bt_md5=findViewById(R.id.bt_md5);
        bt_md5.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()){
            case R.id.bt_sm2:
                optSM2();
                break;
            case R.id.bt_sm3:
                digstSM3();
                break;
            case R.id.bt_sm4:
                optSM4();
                break;
            case R.id.bt_trides:
                optTrisDes();
                break;
            case R.id.bt_onedes:
                optDes();
                break;
            case R.id.bt_aes:
                optAes();
                break;
            case R.id.bt_dsa:
                optDsa();
                break;
            case R.id.bt_rsa:
                optRsa();
                break;
            case R.id.bt_sha1:
                optMacSha1();
                break;
            case R.id.bt_md5:
                optMD5();
                break;
        }
    }

    public void clear(View v){
        text_result.setText("");
        EncryptionManager.reStoreCipher();
    }



    /**
     *国密SM2非对称加密算法，类似RAS，但是安全度以及效率上比之要高。
     */
    private void optSM2(){
        String plainText = et_encryption.getText().toString();
        if(TextUtils.isEmpty(plainText)){
            return;
        }
        long startTime=System.currentTimeMillis();
        AbstractCoder cipher=EncryptionManager.getCipher(EncryptionManager.Model.SM2);
        SM2KeyHelper.KeyPair keyPair=SM2KeyHelper.generateKeyPair((Sm2Kit)cipher);
        //生成密钥对
        String privateKeyHex= keyPair.getPrivateKey();
        String publicKeyHex=keyPair.getPublicKey();
        Log.i("lfp","privateKeyHex.length="+privateKeyHex.length()+",publicKeyHex.length="+publicKeyHex.length());
        try{
            text_result.append("\nSM2加密: \n");
            String cipherText=cipher.simpleEnCode(plainText,publicKeyHex);
            long encryEndTime=System.currentTimeMillis();
            Log.i("lfp","cipherText="+cipherText);
            text_result.append("密文:"+cipherText+"\n耗时："+(encryEndTime-startTime)+"毫秒");
            text_result.append("\n");
            plainText=cipher.simpleDeCode(cipherText,privateKeyHex);
            long dncryEndTime=System.currentTimeMillis();
            text_result.append("解密: \n");
            text_result.append("明文:"+plainText+"\n耗时："+(dncryEndTime-encryEndTime)+"毫秒");
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * 签名计算，相对MD5/SHA1要安全
     */
    private void digstSM3(){
        String plainText = et_encryption.getText().toString();
        if(TextUtils.isEmpty(plainText)){
            return;
        }
        long startTime=System.currentTimeMillis();
        AbstractCoder cipher=EncryptionManager.getCipher(EncryptionManager.Model.SM3);
        String s=cipher.digestSignature(plainText,null);
        //SM3算法需要使用一次后重置
        EncryptionManager.reStoreCipher();
        long endTime=System.currentTimeMillis();
        text_result.append("\n加签: \n");
        text_result.append("签名: "+s+"\n计算签名耗时："+(endTime-startTime)+"毫秒");
    }

    /**
     * 对称加密，类似3DES，比3DES安全
     */
    private void optSM4(){
        String plainText = et_encryption.getText().toString();
        if(TextUtils.isEmpty(plainText)){
            return;
        }
        long startTime=System.currentTimeMillis();
        AbstractCoder cipher=EncryptionManager.getCipher(EncryptionManager.Model.SM4);
        String key=Utils.byteToHex("JeF8U9wHFOMfs2Y8".getBytes());
        text_result.append("\nSM4-ECB模式加密: \n");
        String cipherText =  cipher.simpleEnCode(plainText,key);
        long endTime=System.currentTimeMillis();
        text_result.append("密文: " + cipherText+"\nECB模式加密耗时:"+ (endTime-startTime)+"毫秒");
        text_result.append("\n");
        text_result.append("SM4-ECB模式解密: \n");
        plainText = cipher.simpleDeCode(cipherText,key);
        long decryEndTime=System.currentTimeMillis();
        text_result.append("明文: " + plainText+"\nECB模式解密耗时:"+ (decryEndTime-endTime)+"毫秒");
        text_result.append("\n");
    }

    /**
     * 3des
     */
    private void optTrisDes(){
        String value= et_encryption.getText().toString();
        if(TextUtils.isEmpty(value)){
            return;
        }
        String key="alkjhstr84735281986bdas5";
        long startTime=System.currentTimeMillis();
        AbstractCoder abstractCoder=EncryptionManager.getCipher(EncryptionManager.Model.TRIDES);
//        TriDesKit triDesKit=new TriDesKit();
        String encryResult=Utils.byteToHex(abstractCoder.enCode(value.getBytes(),key.getBytes()));
        long endTime=System.currentTimeMillis();
        text_result.append("3DES加密:\n");
        text_result.append("密文: " + encryResult+"\n耗时:"+ (endTime-startTime)+"毫秒");
        text_result.append("\n");
        text_result.append("3DES解密:\n");
        String DencryResult= new String(abstractCoder.deCode(Utils.hexStringToBytes(encryResult),key.getBytes()));
        long endTime1=System.currentTimeMillis();
        text_result.append("明文: " + DencryResult+"\n耗时:"+ (endTime1-endTime)+"毫秒");
        text_result.append("\n");
    }
    /**
     * aes
     */
    private void optAes(){
        String value=et_encryption.getText().toString();
        if(TextUtils.isEmpty(value)){
            return;
        }
        long startTime=System.currentTimeMillis();
        String rule="9879238423";
        AbstractCoder abstractCoder= EncryptionManager.getCipher(EncryptionManager.Model.AES);
        String ecnryResult= abstractCoder.simpleEnCode(value,rule);
        long endTime=System.currentTimeMillis();
        text_result.append("AES加密:\n");
        text_result.append("密文: " + ecnryResult+"\n耗时:"+ (endTime-startTime)+"毫秒");
        text_result.append("\n");
        String decryResult= abstractCoder.simpleDeCode(ecnryResult,rule);
        long endTime1=System.currentTimeMillis();
        text_result.append("AES解密:\n");
        text_result.append("明文: " + decryResult+"\n耗时:"+ (endTime1-endTime)+"毫秒");
        text_result.append("\n");
    }
    /**
     * rsa
     */
    private void optRsa(){
        String value=et_encryption.getText().toString();
        if(TextUtils.isEmpty(value)){
            return;
        }
        RsaKeyHelper.KeyPass keyPass=RsaKeyHelper.generateKeyPair();
        long startTime=System.currentTimeMillis();
//        RsaKit rsaKit=new RsaKit();
        AbstractCoder abstractCoder= EncryptionManager.getCipher(EncryptionManager.Model.RSA);
        String encryResult=abstractCoder.simpleEnCode(value,keyPass.getPublicKeyHex());
        long endTime=System.currentTimeMillis();
        text_result.append("RSA加密:\n");
        text_result.append("密文: " + encryResult+"\n耗时:"+ (endTime-startTime)+"毫秒");
        text_result.append("\n");
        try {
            String decryResult=abstractCoder.simpleDeCode(encryResult,keyPass.getPrivateKeyHex());
            long endTime1=System.currentTimeMillis();
            text_result.append("RAS解密:\n");
            text_result.append("明文: " + decryResult+"\n耗时:"+ (endTime1-endTime)+"毫秒");
            text_result.append("\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    //适合后台加签，前台校验
    private void optDsa(){
        String value=et_encryption.getText().toString();
        if(TextUtils.isEmpty(value)){
            return;
        }
        long startTime=System.currentTimeMillis();
        String seed="akjh93124kjasfwe23423sd323";
        DSAKeyHelper.KeyPass keyPass=DSAKeyHelper.genKeyPair(seed);
        Log.i("lfp","publicKeyHex"+keyPass.getPublicKeyHex());
        Log.i("lfp","privateKeyHex"+keyPass.getPrivateKeyHex());
//        DSAKit dsaKit=new DSAKit();
        AbstractCoder abstractCoder=EncryptionManager.getCipher(EncryptionManager.Model.DSA);
        String sign=abstractCoder.digestSignature(value,keyPass.getPrivateKeyHex());
        long endTime=System.currentTimeMillis();
        text_result.append("DSA签名:\n");
        text_result.append(sign+"\n");
        boolean flag=abstractCoder.verifyWithDSA(value.getBytes(),sign,Utils.hexStringToBytes(keyPass.getPublicKeyHex()));
        text_result.append("\n"+"耗时："+(endTime-startTime)+"毫秒\n");
        text_result.append("签名校验："+flag);
        text_result.append("\n");
    }
    private void optDes(){
        String plainText = et_encryption.getText().toString();
        if(TextUtils.isEmpty(plainText)){
            return;
        }
        String key="12345678";
        AbstractCoder abstractCoder=EncryptionManager.getCipher(EncryptionManager.Model.DES);
        String result=abstractCoder.simpleEnCode(plainText,key);
        text_result.append("\nDES加密: \n");
        text_result.append(result);
        text_result.append("\nDES解密: \n");
        result=abstractCoder.simpleDeCode(result,key);
        text_result.append(result+"\n");
    }
    private void optMacSha1(){
        String plainText = et_encryption.getText().toString();
        if(TextUtils.isEmpty(plainText)){
            return;
        }
        AbstractCoder abstractCoder=EncryptionManager.getCipher(EncryptionManager.Model.HMAC_SHA1);
        String key="handbabala";
        String signatrue=abstractCoder.digestSignature(plainText,key);
        text_result.append("\nHMAC_SHA1加签: \n");
        text_result.append(signatrue+"\n");
    }
    private void optMD5(){
        String plainText = et_encryption.getText().toString();
        if(TextUtils.isEmpty(plainText)){
            return;
        }
        AbstractCoder abstractCoder=EncryptionManager.getCipher(EncryptionManager.Model.MD5);
        String md5=abstractCoder.digestSignature(plainText,null);
        text_result.append("\nMD5签名: \n");
        text_result.append(md5+"\n");
    }
}
