package com.grepp.spring.infra.error.exceptions;

import com.grepp.spring.infra.response.ResponseCode;

public class AuthApiException extends CommonException{
    
    public AuthApiException(ResponseCode code) {
        super(code);
    }
    
    public AuthApiException(ResponseCode code, Exception e) {
        super(code, e);
    }
}
