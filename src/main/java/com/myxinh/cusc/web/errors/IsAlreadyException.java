package com.myxinh.cusc.web.errors;

public class IsAlreadyException extends RuntimeException{

    public IsAlreadyException(String message) {
        super(message+" is already in use!");
    }
}
