package com.uopen.cryptionkit;

import android.util.Log;

import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.core.aes.AESKit;
import com.uopen.cryptionkit.core.des.OneDesKit;
import com.uopen.cryptionkit.core.des.TriDesKit;
import com.uopen.cryptionkit.core.dsa.DSAKit;
import com.uopen.cryptionkit.core.md5.MD5Kit;
import com.uopen.cryptionkit.core.rsa.RsaKit;
import com.uopen.cryptionkit.core.sha1.HMacSha1Kit;
import com.uopen.cryptionkit.core.sm2.Sm2Kit;
import com.uopen.cryptionkit.core.sm3.Sm3Kit;
import com.uopen.cryptionkit.core.sm4.Sm4Kit;

/**
 * Created by fplei on 2018/9/26.
 */
public class EncryptionManager {
    public enum Model{
        AES,RSA,TRIDES,DES,HMAC_SHA1,DSA,SM2,SM3,SM4,MD5
    }
    private static AbstractCoder abstractCoder=null;
    private static Object object=new Object();
    private static Model currentModel=null;

    /**
     * 获取加密器
     * @param model 加密器模式
     * @return 返回加密器
     */
    public static AbstractCoder getCipher(Model model){
        if(abstractCoder==null||
                (currentModel==null||currentModel!=model)){
            synchronized (object){
                if(abstractCoder==null||
                        (currentModel==null||currentModel!=model)){
                    currentModel=model;
                    switch (model){
                        case AES:
                            abstractCoder=new AESKit();
                            break;
                        case RSA:
                            abstractCoder=new RsaKit();
                            break;
                        case TRIDES:
                            abstractCoder=new TriDesKit();
                            break;
                        case SM2:
                            abstractCoder=new Sm2Kit();
                            break;
                        case SM3:
                            abstractCoder=new Sm3Kit();
                            break;
                        case DES:
                            abstractCoder=new OneDesKit();
                            break;
                        case DSA:
                            abstractCoder=new DSAKit();
                            break;
                        case MD5:
                            abstractCoder=new MD5Kit();
                            break;
                        case HMAC_SHA1:
                            abstractCoder=new HMacSha1Kit();
                            break;
                        case SM4:
                            abstractCoder=new Sm4Kit();
                            break;
                    }
                }
            }
        }

        return abstractCoder;
    }

    /**
     * 重置
     */
    public static void reStoreCipher(){
        abstractCoder=null;
        currentModel=null;
    }
}
