package com.grepp.spring.token.service

import com.fasterxml.jackson.databind.ObjectMapper
import com.grepp.spring.token.entity.RefreshToken
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Service
import java.time.Duration
import java.util.*

@Service
class RefreshTokenService(
    private val redisTemplate: RedisTemplate<String, Any>,
    private val objectMapper: ObjectMapper

) {

    fun saveWithAtId(atId: String): RefreshToken {
        val refreshToken = RefreshToken(accessTokenId = atId)
        redisTemplate.opsForValue()[atId, refreshToken] =
            Duration.ofSeconds(refreshToken.ttl)
        return refreshToken
    }

    fun deleteByAccessTokenId(atId: String) {
        redisTemplate.delete(atId)
    }

    fun renewingToken(id: String, newTokenId: String): RefreshToken? {
        val refreshToken = findByAccessTokenId(id) ?: return null

        // 지연시간 동안 사용할 ttl 10초 짜리
        val gracePeriodToken = RefreshToken(accessTokenId = id)
        gracePeriodToken.token = refreshToken.token

        // 기존 refresh token 변경
        refreshToken.token = UUID.randomUUID().toString()
        refreshToken.accessTokenId = newTokenId

        redisTemplate.opsForValue()[newTokenId, refreshToken] =
            Duration.ofSeconds(refreshToken.ttl)

        redisTemplate.opsForValue()[id, gracePeriodToken] = Duration.ofSeconds(10)
        return refreshToken
    }

    fun findByAccessTokenId(atId: String): RefreshToken? {
        return objectMapper.convertValue(
            redisTemplate.opsForValue()[atId],
            RefreshToken::class.java
        )
    }
}
