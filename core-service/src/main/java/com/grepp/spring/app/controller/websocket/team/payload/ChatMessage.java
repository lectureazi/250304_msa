package com.grepp.spring.app.controller.websocket.team.payload;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import lombok.Data;

@Data
public class ChatMessage {
    
    private String sender;
    private String content;
    private final String createdAt = OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    private final String time = OffsetDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm"));
    
}
