package com.grepp.spring.app.controller.websocket.team;

import com.grepp.spring.app.controller.websocket.team.payload.ChatMessage;
import com.grepp.spring.infra.error.exceptions.CommonException;
import com.grepp.spring.infra.response.ResponseCode;
import com.grepp.spring.infra.response.WebSocketResponse;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;

@Controller
@MessageMapping("team")
public class TeamChatController {

    @MessageMapping("{teamId}/chat")
    @SendTo("/topic/team/{teamId}/chat")
    public WebSocketResponse<ChatMessage> chat(
        String message,
        Authentication authentication
    ){
        ChatMessage chatMessage = new ChatMessage();
        chatMessage.setSender(authentication.getName());
        chatMessage.setContent(message);
        throw new CommonException(ResponseCode.UNAUTHORIZED);
        // return WebSocketResponse.success(chatMessage);
    }

}
