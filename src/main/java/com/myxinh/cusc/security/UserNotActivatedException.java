package com.myxinh.cusc.security;

import org.springframework.security.core.AuthenticationException;

public class UserNotActivatedException extends AuthenticationException {
    public UserNotActivatedException(String message) {
        super(message);
    }
}
