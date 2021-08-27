package com.myxinh.cusc.web.errors;

public class BadRequestAlertException extends RuntimeException{

    public BadRequestAlertException(String message) {
        super("A new category cannot already have an ID:"+message);
    }

}
