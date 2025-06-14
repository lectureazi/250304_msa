package com.grepp.spring.app.controller.api.student;

import com.grepp.spring.app.controller.api.student.payload.StudentRecommendRequest;
import com.grepp.spring.app.controller.api.student.payload.StudentRecommendResponse;
import com.grepp.spring.app.model.student.StudentAiService;
import com.grepp.spring.app.model.student.code.Sentimental;
import com.grepp.spring.infra.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("api/ai")
public class StudentApiController {
    
    private final StudentAiService studentAiService;
    
    @GetMapping("chat")
    public String chat(String message){
        return studentAiService.chat(message);
    }
    
    @GetMapping("classify")
    public ResponseEntity<ApiResponse<Sentimental>> classify(String message){
        return ResponseEntity.ok(ApiResponse.success(
            studentAiService.classify(message)
        ));
    }
    
    @GetMapping("recommend/team")
    public ResponseEntity<ApiResponse<StudentRecommendResponse>> recommendTeam(
        StudentRecommendRequest request
    ){
        return ResponseEntity.ok(ApiResponse.success(studentAiService.recommendTeam(request)));
    }
}
