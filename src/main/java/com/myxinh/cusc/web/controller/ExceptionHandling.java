package com.myxinh.cusc.web.controller;

import com.myxinh.cusc.service.dto.ErrorResponse;
import com.myxinh.cusc.web.errors.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class ExceptionHandling extends ResponseEntityExceptionHandler {

    public ExceptionHandling() {
    }

    @ExceptionHandler(value = {BadCredentialsException.class})
    protected ResponseEntity<Object> handleException(RuntimeException ex, WebRequest request){
        String path = ((ServletWebRequest)request).getRequest().getRequestURI();
        ErrorResponse error = new ErrorResponse(HttpStatus.FORBIDDEN.value(),ex.getMessage(),path);
        return handleExceptionInternal(ex,error,new HttpHeaders(),HttpStatus.UNAUTHORIZED,request);
    }

    @ExceptionHandler(value = {BadRequestAlertException.class})
    protected ResponseEntity<Object> handleBadRequestAlertException(RuntimeException ex,WebRequest request){
        String path = ((ServletWebRequest)request).getRequest().getRequestURI();
        ErrorResponse error = new ErrorResponse(HttpStatus.BAD_REQUEST.value(),ex.getMessage(),path);
        return handleExceptionInternal(ex,error,new HttpHeaders(),HttpStatus.BAD_REQUEST,request);
    }

    @ExceptionHandler(value = {IsAlreadyException.class})
    protected ResponseEntity<Object> handleIsAlreadyException(RuntimeException ex,WebRequest request){
        String path = ((ServletWebRequest)request).getRequest().getRequestURI();
        ErrorResponse error = new ErrorResponse(HttpStatus.BAD_REQUEST.value(),ex.getMessage(),path);
        return handleExceptionInternal(ex,error,new HttpHeaders(),HttpStatus.BAD_REQUEST,request);
    }

    @ExceptionHandler(value = {NotFoundException.class})
    protected ResponseEntity<Object> handleNotFoundException(RuntimeException ex,WebRequest request){
        String path = ((ServletWebRequest)request).getRequest().getRequestURI();
        ErrorResponse error = new ErrorResponse(HttpStatus.NO_CONTENT.value(),ex.getMessage(),path);
        return handleExceptionInternal(ex,error,new HttpHeaders(),HttpStatus.BAD_REQUEST,request);
    }

    @ExceptionHandler(value = {ExistMainNewsException.class})
    protected ResponseEntity<Object> handleIsMainNewsException(RuntimeException ex,WebRequest request){
        String path = ((ServletWebRequest)request).getRequest().getRequestURI();
        ErrorResponse error = new ErrorResponse(HttpStatus.CONFLICT.value(),ex.getMessage(),path);
        return handleExceptionInternal(ex,error,new HttpHeaders(),HttpStatus.CONFLICT,request);
    }

    @ExceptionHandler(value = {NullException.class})
    protected ResponseEntity<Object> handleNullPointerException(RuntimeException ex,WebRequest request){
        String path = ((ServletWebRequest)request).getRequest().getRequestURI();
        ErrorResponse error = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(),ex.getMessage(),path);
        return handleExceptionInternal(ex,error,new HttpHeaders(),HttpStatus.INTERNAL_SERVER_ERROR,request);
    }

    @ExceptionHandler(value = {DateLogicException.class})
    protected ResponseEntity<Object> handleDateException(RuntimeException ex,WebRequest request){
        String path = ((ServletWebRequest)request).getRequest().getRequestURI();
        ErrorResponse error = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(),ex.getMessage(),path);
        return handleExceptionInternal(ex,error,new HttpHeaders(),HttpStatus.INTERNAL_SERVER_ERROR,request);
    }
}
