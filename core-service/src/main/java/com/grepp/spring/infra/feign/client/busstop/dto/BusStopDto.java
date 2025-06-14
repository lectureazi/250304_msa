package com.grepp.spring.infra.feign.client.busstop.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class BusStopDto {

    @JsonProperty("NODE_ID")
    private Long id;
    @JsonProperty("STOPS_NO")
    private String stopsNumber;
    @JsonProperty("STOPS_NM")
    private String name;
    @JsonProperty("XCRD")
    private String longitude;
    @JsonProperty("YCRD")
    private String latitude;
    @JsonProperty("STOPS_TYPE")
    private String type;
    
}
