package com.myxinh.cusc.service.utils;

import com.myxinh.cusc.web.errors.DateLogicException;
import com.myxinh.cusc.web.errors.ErrorConstants;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.util.SerializationUtils;

import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class SystemUtils {
    public static String serializeData(String original){
        byte[] input = SerializationUtils.serialize((original));
        return Base64.encodeBase64String(input);
    }

    public static String deserializeData(String encrypted){
        try{
            boolean isBase64 = Base64.isBase64(encrypted);
            if (isBase64){
                byte[]decodeOutput = Base64.decodeBase64(encrypted);
                return (String) SerializationUtils.deserialize(decodeOutput);
            }
            return encrypted;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static String getDate(String data){
        return data.substring(0,10);
    }

    public static boolean checkDateLogic(String startDate,String endDate) throws ParseException {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");
        Date lits_bddk = simpleDateFormat.parse(startDate);
        Date lits_ktdk = simpleDateFormat.parse(endDate);
        return lits_bddk.before(lits_ktdk) && lits_ktdk.after(lits_bddk);

    }
}
