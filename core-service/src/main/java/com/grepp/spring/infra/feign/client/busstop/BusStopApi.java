package com.grepp.spring.infra.feign.client.busstop;

import com.grepp.spring.infra.feign.client.busstop.config.BusStopConfig;
import com.grepp.spring.infra.feign.client.busstop.dto.BusStopResponse;
import com.grepp.spring.infra.feign.config.FeignCommonConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(
    name = "bus-stop-api",
    url = "http://openapi.seoul.go.kr:8088/",
    configuration = {BusStopConfig.class, FeignCommonConfig.class})
public interface BusStopApi {
    @GetMapping("{apiKey}/json/busStopLocationXyInfo/{startIndex}/{endIndex}")
    BusStopResponse getBusStop(
        @PathVariable
        String apiKey,
        @PathVariable
        int startIndex,
        @PathVariable
        int endIndex
    );
}
