package com.grepp.spring.app.controller.websocket.team

import com.grepp.spring.app.controller.websocket.team.payload.ChatMessage
import com.grepp.spring.infra.response.WebSocketResponse
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.messaging.handler.annotation.MessageMapping
import org.springframework.messaging.handler.annotation.SendTo
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

@Controller
@MessageMapping("chat")
class TeamChatController(
    private val redisTemplate: RedisTemplate<String, String>
) {

    @GetMapping("/")
    fun index(): String {
        return "team/team"
    }

    @MessageMapping("")
    fun chat( message: ChatMessage){
        redisTemplate.convertAndSend("chat", message)
    }
}
