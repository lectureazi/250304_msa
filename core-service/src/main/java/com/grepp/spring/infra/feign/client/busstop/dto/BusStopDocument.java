package com.grepp.spring.infra.feign.client.busstop.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record BusStopDocument(
    @JsonProperty("list_total_count")
    int totalCount,
    BusStopResult RESULT,
    List<BusStopDto> row
) {

}
