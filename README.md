Android加密工具集合，包括：
1 RSA
2 AES
3 3DES/DES
4 HMAC_SHA1
5 国密SM2/SM3/SM4
6 MD5
7 DSA

简单使用方法
调用eg1（SM4对称加密）：
AbstractCoder cipher=EncryptionManager.getCipher(EncryptionManager.Model.SM4);
//调用简单加密方法
String cipherText =  cipher.simpleEnCode(plainText,key);
//解密
plainText = cipher.simpleDeCode(cipherText,key);
---------
调用eg2(DSA验签)：
//密钥对生成种子
String seed="akjh93124kjasfwe23423sd323";
//生成密钥对
DSAKeyHelper.KeyPass keyPass=DSAKeyHelper.genKeyPair(seed);
//获取加密器
AbstractCoder abstractCoder=EncryptionManager.getCipher(EncryptionManager.Model.DSA);
//计算签名
String sign=abstractCoder.digestSignature(value,keyPass.getPrivateKeyHex());
//验证签名
boolean flag=abstractCoder.verifyWithDSA(value.getBytes(),sign,Utils.hexStringToBytes(keyPass.getPublicKeyHex()));

具体使用方法请见例子！
