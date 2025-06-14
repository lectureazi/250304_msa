package com.grepp.spring.app.controller.websocket.team.payload

import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter

data class ChatMessage(
    var sender: String,
    val content: String,
    val createdAt: String =
        OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
    val time: String = OffsetDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm"))
) {
}
