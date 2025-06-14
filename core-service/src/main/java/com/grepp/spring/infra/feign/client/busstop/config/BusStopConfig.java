package com.grepp.spring.infra.feign.client.busstop.config;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.grepp.spring.infra.feign.client.busstop.decoder.BusStopErrorDecoder;
import com.grepp.spring.infra.feign.client.busstop.dto.BusStopResult;
import com.grepp.spring.infra.feign.error.FeignCommonException;
import feign.FeignException;
import feign.Response;
import feign.ResponseInterceptor;
import feign.codec.ErrorDecoder;
import java.io.InputStream;
import java.util.Collection;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;

public class BusStopConfig {
    
    @Bean
    public ErrorDecoder errorDecoder(){
        return (s, response) -> {
            HttpStatus status = HttpStatus.valueOf(response.status());
            return new FeignCommonException("", "", status);
        };
    }
    
    @Bean
    public ResponseInterceptor busStopInterceptor(){
        return (invocationContext, chain) -> {
            Response response = invocationContext.response();
            
            XmlMapper xmlMapper = new XmlMapper();
            HttpStatus status = HttpStatus.valueOf(response.status());
            
            Collection<String> contentType = response.headers().get("content-type");
            if(contentType == null){
                return chain.next(invocationContext);
            }
            
            if(contentType.contains("application/xml;charset=UTF-8")){
                try(InputStream body = response.body().asInputStream()){
                    BusStopResult error = xmlMapper.readValue(body, BusStopResult.class);
                    throw new FeignCommonException(error.CODE(), error.MESSAGE(), status);
                }
            }
            return chain.next(invocationContext);
        };
    }
    
}
