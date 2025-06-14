package com.grepp.spring.app.model.rent.dto;

import com.grepp.spring.app.model.rent.code.RentState;
import java.time.LocalDate;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class RentBookDto {
    private Long id;
    private Long bookId;
    private String bookTitle;
    private RentState state;
    private LocalDate returnDate;
}
