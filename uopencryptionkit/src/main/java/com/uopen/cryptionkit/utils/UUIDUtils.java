package com.uopen.cryptionkit.utils;

import java.util.UUID;

/**
 * 生成UUID
 */
public class UUIDUtils {
    /**
     * 生成一个唯一标识
     * @return
     */
    public static String getUUIDWithTime(){
        String tempid=UUID.randomUUID().toString();
        return System.currentTimeMillis()+tempid.replaceAll("-","");
    }
    public static String getUUID(){
        String tempid=UUID.randomUUID().toString();
        return tempid.replaceAll("-","");
    }
    /**
     * 获得指定数目的UUID
     * @param number int 需要获得的UUID数量
     * @return String[] UUID数组
     */
    public static String[] getUUID(int number){
        if(number < 1){
            return null;
        }
        String[] retArray = new String[number];
        for(int i=0;i<number;i++){
            retArray[i] = getUUIDWithTime();
        }
        return retArray;
    }

}
