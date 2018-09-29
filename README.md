Android加密工具集合，包括：
1 RSA<br /> 
2 AES<br /> 
3 3DES/DES<br /> 
4 HMAC_SHA1<br /> 
5 国密SM2/SM3/SM4<br /> 
6 MD5<br /> 
7 DSA<br /> 

简单使用方法<br /> 
调用eg1（SM4对称加密）：<br /> 
AbstractCoder cipher=EncryptionManager.getCipher(EncryptionManager.Model.SM4);<br /> 
//调用简单加密方法<br /> 
String cipherText =  cipher.simpleEnCode(plainText,key);<br /> 
//解密<br /> 
plainText = cipher.simpleDeCode(cipherText,key);<br /> 
---------<br /> 
调用eg2(DSA验签)：<br /> 
//密钥对生成种子<br /> 
String seed="akjh93124kjasfwe23423sd323";<br /> 
//生成密钥对<br /> 
DSAKeyHelper.KeyPass keyPass=DSAKeyHelper.genKeyPair(seed);<br /> 
//获取加密器<br /> 
AbstractCoder abstractCoder=EncryptionManager.getCipher(EncryptionManager.Model.DSA);<br /> 
//计算签名<br /> 
String sign=abstractCoder.digestSignature(value,keyPass.getPrivateKeyHex());<br /> 
//验证签名<br /> 
boolean flag=abstractCoder.verifyWithDSA(value.getBytes(),sign,Utils.hexStringToBytes(keyPass.getPublicKeyHex()));<br /> 

具体使用方法请见例子！
