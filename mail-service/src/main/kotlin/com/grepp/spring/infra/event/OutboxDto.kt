package com.grepp.spring.infra.event

import java.time.LocalDateTime

data class OutboxDto(
    val eventId:String,
    val eventType:String,
    val sourceService: String,
    val payload: String,
    val createdAt: LocalDateTime,
    val modifiedAt: LocalDateTime,
    val activated: Boolean
    ) {
}