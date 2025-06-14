package com.grepp.spring.app.controller.api.student.payload;

import com.grepp.spring.app.model.student.dto.StudentDto;
import java.util.List;

public record StudentRecommendResponse(
    List<StudentDto> studentDtos,
    String reason
) {

}
