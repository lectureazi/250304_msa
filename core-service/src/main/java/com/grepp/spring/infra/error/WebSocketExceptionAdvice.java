package com.grepp.spring.infra.error;

import com.grepp.spring.infra.error.exceptions.CommonException;
import com.grepp.spring.infra.response.WebSocketResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.handler.annotation.MessageExceptionHandler;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.web.bind.annotation.ControllerAdvice;

@ControllerAdvice(basePackages = "com.grepp.spring.app.controller.websocket")
@Slf4j
public class WebSocketExceptionAdvice {

    @MessageExceptionHandler(CommonException.class)
    // destinations = "/queue/errors"
    // /user/{username}/queue/errors
    @SendToUser(destinations = "/queue/errors", broadcast = false)
    public WebSocketResponse<Void> commonExHandler(CommonException ex){
        return WebSocketResponse.error(ex.code());
    }
}
