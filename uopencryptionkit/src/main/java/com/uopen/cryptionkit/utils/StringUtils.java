package com.uopen.cryptionkit.utils;

/**
 * Created by fplei on 2018/9/21.
 */

public class StringUtils {

    public static boolean isNull(String value){
        if(value!=null&&value.length()>0){
            return false;
        }
        return true;
    }
}
