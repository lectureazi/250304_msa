package com.grepp.spring.infra.event

import org.springframework.data.jpa.repository.JpaRepository

interface OutboxRepository : JpaRepository<Outbox, String> {
    fun findByActivatedIsTrueOrderByCreatedAt():List<Outbox>
}