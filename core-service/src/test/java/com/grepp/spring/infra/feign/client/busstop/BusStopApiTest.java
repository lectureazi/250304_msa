package com.grepp.spring.infra.feign.client.busstop;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class BusStopApiTest {

    @Autowired
    BusStopApi busStopApi;
    
    @Value("${bus-stop.apikey}")
    String apiKey;

}