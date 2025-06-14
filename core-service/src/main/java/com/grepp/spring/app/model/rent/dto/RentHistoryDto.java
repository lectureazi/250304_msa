package com.grepp.spring.app.model.rent.dto;

import com.grepp.spring.app.model.rent.code.RentState;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class RentHistoryDto {
    private Long id;
    private RentDto rentDto;
    private RentBookDto rentBookDto;
    private Long bookId;
    private RentState state;
}
