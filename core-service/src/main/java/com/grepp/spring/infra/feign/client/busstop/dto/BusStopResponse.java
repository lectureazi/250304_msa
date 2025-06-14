package com.grepp.spring.infra.feign.client.busstop.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record BusStopResponse(
    @JsonProperty("busStopLocationXyInfo")
    BusStopDocument document
) {

}
