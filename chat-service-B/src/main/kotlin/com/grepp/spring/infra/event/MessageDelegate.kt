package com.grepp.spring.infra.event

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.grepp.spring.app.controller.websocket.team.payload.ChatMessage
import com.grepp.spring.infra.response.WebSocketResponse
import org.slf4j.LoggerFactory
import org.springframework.messaging.simp.SimpMessageSendingOperations
import org.springframework.stereotype.Component


interface MessageDelegate {
    fun handleMessage(message: String)
}

@Component
class EventMessageDelegate(
    private val objectMapper: ObjectMapper,
    private val operator: SimpMessageSendingOperations
) : MessageDelegate {
    private val log = LoggerFactory.getLogger(javaClass)

    override fun handleMessage(message: String){
        log.info(message)
        val chatMessage = objectMapper.readValue(message, ChatMessage::class.java)

        operator.convertAndSend("/topic/chat",
            WebSocketResponse.success(chatMessage))
    }
}