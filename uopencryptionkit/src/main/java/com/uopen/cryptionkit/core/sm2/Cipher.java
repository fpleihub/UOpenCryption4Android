package com.uopen.cryptionkit.core.sm2;

import com.uopen.cryptionkit.core.sm3.Sm3Kit;
import com.uopen.cryptionkit.utils.Utils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Created by fplei on 2018/9/21.
 */
public class Cipher {
    private int ct;
    private ECPoint p2;
    private Sm3Kit sm3keybase;
    private Sm3Kit sm3c3;
    private byte key[];
    private byte keyOff;

    public Cipher()
    {
        this.ct = 1;
        this.key = new byte[32];
        this.keyOff = 0;
    }

    private void Reset()
    {
        this.sm3keybase = new Sm3Kit();
        this.sm3c3 = new Sm3Kit();

        byte p[] = Utils.byteConvert32Bytes(p2.getX().toBigInteger());
        this.sm3keybase.update(p, 0, p.length);
        this.sm3c3.update(p, 0, p.length);

        p = Utils.byteConvert32Bytes(p2.getY().toBigInteger());
        this.sm3keybase.update(p, 0, p.length);
        this.ct = 1;
        NextKey();
    }

    private void NextKey()
    {
        Sm3Kit sm3keycur = new Sm3Kit(this.sm3keybase);
        sm3keycur.update((byte) (ct >> 24 & 0xff));
        sm3keycur.update((byte) (ct >> 16 & 0xff));
        sm3keycur.update((byte) (ct >> 8 & 0xff));
        sm3keycur.update((byte) (ct & 0xff));
        sm3keycur.doFinal(key, 0);
        this.keyOff = 0;
        this.ct++;
    }

    public ECPoint Init_enc(Sm2Kit sm2Kit, ECPoint userKey)
    {
        AsymmetricCipherKeyPair key = sm2Kit.ecc_key_pair_generator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
        BigInteger k = ecpriv.getD();
        ECPoint c1 = ecpub.getQ();
        this.p2 = userKey.multiply(k);
        Reset();
        return c1;
    }

    public void Encrypt(byte data[])
    {
        this.sm3c3.update(data, 0, data.length);
        for (int i = 0; i < data.length; i++)
        {
            if (keyOff == key.length)
            {
                NextKey();
            }
            data[i] ^= key[keyOff++];
        }
    }

    public void Init_dec(BigInteger userD, ECPoint c1)
    {
        this.p2 = c1.multiply(userD);
        Reset();
    }

    public void Decrypt(byte data[])
    {
        for (int i = 0; i < data.length; i++)
        {
            if (keyOff == key.length)
            {
                NextKey();
            }
            data[i] ^= key[keyOff++];
        }

        this.sm3c3.update(data, 0, data.length);
    }

    public void Dofinal(byte c3[])
    {
        byte p[] = Utils.byteConvert32Bytes(p2.getY().toBigInteger());
        this.sm3c3.update(p, 0, p.length);
        this.sm3c3.doFinal(c3, 0);
        Reset();
    }
}
