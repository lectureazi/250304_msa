package com.grepp.spring.infra.feign.client.busstop.decoder;

import com.grepp.spring.infra.feign.error.FeignCommonException;
import feign.Response;
import feign.codec.ErrorDecoder;
import org.springframework.http.HttpStatus;

public class BusStopErrorDecoder implements ErrorDecoder {
    
    @Override
    public Exception decode(String s, Response response) {
        HttpStatus status = HttpStatus.valueOf(response.status());
        return new FeignCommonException("", "", status);
    }
}
