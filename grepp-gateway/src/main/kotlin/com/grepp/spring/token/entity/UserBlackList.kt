package com.grepp.spring.token.entity

import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash
import java.time.OffsetDateTime

@RedisHash("userBlackList")
class UserBlackList(
    @Id
    val email: String,
    val createdAt: OffsetDateTime = OffsetDateTime.now()
)