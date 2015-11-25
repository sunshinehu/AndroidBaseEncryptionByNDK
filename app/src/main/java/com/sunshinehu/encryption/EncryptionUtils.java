package com.sunshinehu.encryption;

import android.content.Context;

/**
 * Created by huchenxi on 2015/11/18.
 */
public class EncryptionUtils {

    static {

        //加载运行库
        System.loadLibrary("encryption");

    }

    //使用ascii 偏移加密
    public static native String  encodeMethod1(String origin,String code);
    public static native String  decodeMethod1(String result,String code);


    //直接传入原始字符串进行加密，在原生代码中进行签名校验和加解密操作
    public static native int[] encodeMethod2(String origin,Context context);
    public static native String decodeMethod2(String result,Context context);

    public static native int[] getCode();

}
