package com.myxinh.cusc.web.errors;

public class NullException extends RuntimeException{

    public NullException(String message) {
        super(message + " can not be null");
    }
}
