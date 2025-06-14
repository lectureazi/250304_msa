package com.grepp.spring.infra.error;

import com.grepp.spring.infra.error.exceptions.AuthApiException;
import com.grepp.spring.infra.error.exceptions.AuthWebException;
import com.grepp.spring.infra.response.ApiResponse;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@ControllerAdvice
@RequiredArgsConstructor
public class AuthExceptionAdvice {
    
    private final TemplateEngine templateEngine;

    @ResponseBody
    @ExceptionHandler(AuthApiException.class)
    public ResponseEntity<ApiResponse<String>> authApiExHandler(AuthApiException ex){
        return ResponseEntity.status(ex.code().status())
                   .body(ApiResponse.error(ex.code()));
    }
    
    @ResponseBody
    @ExceptionHandler(AuthWebException.class)
    public String authWebExHandler(AuthWebException ex){
        // filter 에서 handlerExceptionResolver 를 직접 부르기 때문에 viewResolver 가 동작하지 않음
        // 직접 templateEngin 을 사용해 html 을 랜더링 한 후 응답
        return render("/error/redirect", Map.of("message", ex.code().message()
            , "redirect", ex.redirect()));
    }
    
    private String render(String path, Map<String, Object> properties){
        Context context = new Context();
        context.setVariables(properties);
        return templateEngine.process(path, context);
    }


}