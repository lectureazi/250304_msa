package com.grepp.spring.infra.event

import com.grepp.spring.infra.entity.BaseEntity
import jakarta.persistence.Entity
import jakarta.persistence.Id
import java.util.UUID

@Entity
class Outbox(
    @Id
    val eventId:String = UUID.randomUUID().toString(),
    val eventType:String,
    val sourceService: String = "user-service",
    val payload: String
):BaseEntity() {

}