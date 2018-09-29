package com.uopen.cryptionkit.core.sm3;

import android.text.TextUtils;

import com.uopen.cryptionkit.core.AbstractCoder;
import com.uopen.cryptionkit.utils.Utils;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;

/**
 * Created by fplei on 2018/9/21.
 * 国密杂凑签名算法
 */
public class Sm3Kit extends AbstractCoder{
    /** SM3值的长度 */
    private static final int BYTE_LENGTH = 32;

    /** SM3分组长度 */
    private static final int BLOCK_LENGTH = 64;

    /** 缓冲区长度 */
    private static final int BUFFER_LENGTH = BLOCK_LENGTH * 1;

    /** 缓冲区 */
    private byte[] xBuf = new byte[BUFFER_LENGTH];

    /** 缓冲区偏移量 */
    private int xBufOff;

    /** 初始向量 */
    private byte[] V = iv.clone();

    private int cntBlock = 0;
    public static final byte[] iv = { 0x73, (byte) 0x80, 0x16, 0x6f, 0x49,
            0x14, (byte) 0xb2, (byte) 0xb9, 0x17, 0x24, 0x42, (byte) 0xd7,
            (byte) 0xda, (byte) 0x8a, 0x06, 0x00, (byte) 0xa9, 0x6f, 0x30,
            (byte) 0xbc, (byte) 0x16, 0x31, 0x38, (byte) 0xaa, (byte) 0xe3,
            (byte) 0x8d, (byte) 0xee, 0x4d, (byte) 0xb0, (byte) 0xfb, 0x0e,
            0x4e };

    public static int[] Tj = new int[64];
    static
    {
        for (int i = 0; i < 16; i++)
        {
            Tj[i] = 0x79cc4519;
        }

        for (int i = 16; i < 64; i++)
        {
            Tj[i] = 0x7a879d8a;
        }
    }
    public Sm3Kit() {
    }

    public Sm3Kit(Sm3Kit t)
    {
        System.arraycopy(t.xBuf, 0, this.xBuf, 0, t.xBuf.length);
        this.xBufOff = t.xBufOff;
        System.arraycopy(t.V, 0, this.V, 0, t.V.length);
    }

    /**
     * SM3结果输出
     *
     * @param out 保存SM3结构的缓冲区
     * @param outOff 缓冲区偏移量
     * @return
     */
    public int doFinal(byte[] out, int outOff)
    {
        byte[] tmp = doFinal();
        System.arraycopy(tmp, 0, out, 0, tmp.length);
        return BYTE_LENGTH;
    }

    public void reset()
    {
        xBufOff = 0;
        cntBlock = 0;
        V = iv.clone();
    }

    /**
     * 明文输入
     * @param in
     *            明文输入缓冲区
     * @param inOff
     *            缓冲区偏移量
     * @param len
     *            明文长度
     */
    public void update(byte[] in, int inOff, int len){
        int partLen = BUFFER_LENGTH - xBufOff;
        int inputLen = len;
        int dPos = inOff;
        if (partLen < inputLen)
        {
            System.arraycopy(in, dPos, xBuf, xBufOff, partLen);
            inputLen -= partLen;
            dPos += partLen;
            doUpdate();
            while (inputLen > BUFFER_LENGTH)
            {
                System.arraycopy(in, dPos, xBuf, 0, BUFFER_LENGTH);
                inputLen -= BUFFER_LENGTH;
                dPos += BUFFER_LENGTH;
                doUpdate();
            }
        }
        System.arraycopy(in, dPos, xBuf, xBufOff, inputLen);
        xBufOff += inputLen;
    }

    private void doUpdate(){
        byte[] B = new byte[BLOCK_LENGTH];
        for (int i = 0; i < BUFFER_LENGTH; i += BLOCK_LENGTH)
        {
            System.arraycopy(xBuf, i, B, 0, B.length);
            doHash(B);
        }
        xBufOff = 0;
    }

    private void doHash(byte[] B){
        byte[] tmp = CF(V, B);
        System.arraycopy(tmp, 0, V, 0, V.length);
        cntBlock++;
    }

    private byte[] doFinal(){
        byte[] B = new byte[BLOCK_LENGTH];
        byte[] buffer = new byte[xBufOff];
        System.arraycopy(xBuf, 0, buffer, 0, buffer.length);
        byte[] tmp = padding(buffer, cntBlock);
        for (int i = 0; i < tmp.length; i += BLOCK_LENGTH){
            System.arraycopy(tmp, i, B, 0, B.length);
            doHash(B);
        }
        return V;
    }

    public void update(byte in)
    {
        byte[] buffer = new byte[] { in };
        update(buffer, 0, 1);
    }

    public int getDigestSize()
    {
        return BYTE_LENGTH;
    }




    public byte[] CF(byte[] V, byte[] B)
    {
        int[] v, b;
        v = convert(V);
        b = convert(B);
        return convert(CF(v, b));
    }

    private int[] convert(byte[] arr)
    {
        int[] out = new int[arr.length / 4];
        byte[] tmp = new byte[4];
        for (int i = 0; i < arr.length; i += 4)
        {
            System.arraycopy(arr, i, tmp, 0, 4);
            out[i / 4] = bigEndianByteToInt(tmp);
        }
        return out;
    }

    private byte[] convert(int[] arr)
    {
        byte[] out = new byte[arr.length * 4];
        byte[] tmp = null;
        for (int i = 0; i < arr.length; i++)
        {
            tmp = bigEndianIntToByte(arr[i]);
            System.arraycopy(tmp, 0, out, i * 4, 4);
        }
        return out;
    }

    public int[] CF(int[] V, int[] B)
    {
        int a, b, c, d, e, f, g, h;
        int ss1, ss2, tt1, tt2;
        a = V[0];
        b = V[1];
        c = V[2];
        d = V[3];
        e = V[4];
        f = V[5];
        g = V[6];
        h = V[7];

        int[][] arr = expand(B);
        int[] w = arr[0];
        int[] w1 = arr[1];

        for (int j = 0; j < 64; j++)
        {
            ss1 = (bitCycleLeft(a, 12) + e + bitCycleLeft(Tj[j], j));
            ss1 = bitCycleLeft(ss1, 7);
            ss2 = ss1 ^ bitCycleLeft(a, 12);
            tt1 = FFj(a, b, c, j) + d + ss2 + w1[j];
            tt2 = GGj(e, f, g, j) + h + ss1 + w[j];
            d = c;
            c = bitCycleLeft(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = bitCycleLeft(f, 19);
            f = e;
            e = P0(tt2);
        }
        int[] out = new int[8];
        out[0] = a ^ V[0];
        out[1] = b ^ V[1];
        out[2] = c ^ V[2];
        out[3] = d ^ V[3];
        out[4] = e ^ V[4];
        out[5] = f ^ V[5];
        out[6] = g ^ V[6];
        out[7] = h ^ V[7];

        return out;
    }

    private int[][] expand(int[] B)
    {
        int W[] = new int[68];
        int W1[] = new int[64];
        for (int i = 0; i < B.length; i++)
        {
            W[i] = B[i];
        }

        for (int i = 16; i < 68; i++)
        {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ bitCycleLeft(W[i - 3], 15))
                    ^ bitCycleLeft(W[i - 13], 7) ^ W[i - 6];
        }

        for (int i = 0; i < 64; i++)
        {
            W1[i] = W[i] ^ W[i + 4];
        }

        int arr[][] = new int[][] { W, W1 };
        return arr;
    }

    private byte[] bigEndianIntToByte(int num)
    {
        return back(Utils.intToBytes(num));
    }

    private int bigEndianByteToInt(byte[] bytes)
    {
        return Utils.byteToInt(back(bytes));
    }

    private int FFj(int X, int Y, int Z, int j)
    {
        if (j >= 0 && j <= 15)
        {
            return FF1j(X, Y, Z);
        }
        else
        {
            return FF2j(X, Y, Z);
        }
    }

    private int GGj(int X, int Y, int Z, int j)
    {
        if (j >= 0 && j <= 15)
        {
            return GG1j(X, Y, Z);
        }
        else
        {
            return GG2j(X, Y, Z);
        }
    }

    // 逻辑位运算函数
    private int FF1j(int X, int Y, int Z)
    {
        int tmp = X ^ Y ^ Z;
        return tmp;
    }

    private int FF2j(int X, int Y, int Z)
    {
        int tmp = ((X & Y) | (X & Z) | (Y & Z));
        return tmp;
    }

    private int GG1j(int X, int Y, int Z)
    {
        int tmp = X ^ Y ^ Z;
        return tmp;
    }

    private int GG2j(int X, int Y, int Z)
    {
        int tmp = (X & Y) | (~X & Z);
        return tmp;
    }

    private int P0(int X)
    {
        int y = rotateLeft(X, 9);
        y = bitCycleLeft(X, 9);
        int z = rotateLeft(X, 17);
        z = bitCycleLeft(X, 17);
        int t = X ^ y ^ z;
        return t;
    }

    private int P1(int X)
    {
        int t = X ^ bitCycleLeft(X, 15) ^ bitCycleLeft(X, 23);
        return t;
    }

    /**
     * 对最后一个分组字节数据padding
     *
     * @param in
     * @param bLen
     *            分组个数
     * @return
     */
    public byte[] padding(byte[] in, int bLen)
    {
        int k = 448 - (8 * in.length + 1) % 512;
        if (k < 0)
        {
            k = 960 - (8 * in.length + 1) % 512;
        }
        k += 1;
        byte[] padd = new byte[k / 8];
        padd[0] = (byte) 0x80;
        long n = in.length * 8 + bLen * 512;
        byte[] out = new byte[in.length + k / 8 + 64 / 8];
        int pos = 0;
        System.arraycopy(in, 0, out, 0, in.length);
        pos += in.length;
        System.arraycopy(padd, 0, out, pos, padd.length);
        pos += padd.length;
        byte[] tmp = back(Utils.longToBytes(n));
        System.arraycopy(tmp, 0, out, pos, tmp.length);
        return out;
    }

    /**
     * 字节数组逆序
     *
     * @param in
     * @return
     */
    private byte[] back(byte[] in)
    {
        byte[] out = new byte[in.length];
        for (int i = 0; i < out.length; i++)
        {
            out[i] = in[out.length - i - 1];
        }

        return out;
    }

    public int rotateLeft(int x, int n)
    {
        return (x << n) | (x >> (32 - n));
    }

    private int bitCycleLeft(int n, int bitLen)
    {
        bitLen %= 32;
        byte[] tmp = bigEndianIntToByte(n);
        int byteLen = bitLen / 8;
        int len = bitLen % 8;
        if (byteLen > 0)
        {
            tmp = byteCycleLeft(tmp, byteLen);
        }

        if (len > 0)
        {
            tmp = bitSmall8CycleLeft(tmp, len);
        }

        return bigEndianByteToInt(tmp);
    }

    private byte[] bitSmall8CycleLeft(byte[] in, int len)
    {
        byte[] tmp = new byte[in.length];
        int t1, t2, t3;
        for (int i = 0; i < tmp.length; i++)
        {
            t1 = (byte) ((in[i] & 0x000000ff) << len);
            t2 = (byte) ((in[(i + 1) % tmp.length] & 0x000000ff) >> (8 - len));
            t3 = (byte) (t1 | t2);
            tmp[i] = (byte) t3;
        }

        return tmp;
    }

    private byte[] byteCycleLeft(byte[] in, int byteLen)
    {
        byte[] tmp = new byte[in.length];
        System.arraycopy(in, byteLen, tmp, 0, in.length - byteLen);
        System.arraycopy(in, 0, tmp, in.length - byteLen, byteLen);
        return tmp;
    }
    @Override
    public String simpleEnCode(String value, String key) {return null;}
    @Override
    public byte[] enCode(byte[] value, byte[] key) {return null;}
    @Override
    public String simpleDeCode(String value, String key){
        return null;
    }
    @Override
    public byte[] deCode(byte[] value, byte[] key) {
        return null;
    }
    @Override
    public String digestSignature(String data, String key) {
        if(data==null){
            return null;
        }
        byte[] sign= digestSignature(data.getBytes(),null);
        return Utils.byteToHex(sign);
    }

    @Override
    public byte[] digestSignature(byte[] data, byte[] key) {
        if(data!=null){
            byte[] md = new byte[32];
            byte[] msg1 = data;
            update(msg1, 0, msg1.length);
            doFinal(md, 0);
            return md;
        }
        return null;
    }
}
