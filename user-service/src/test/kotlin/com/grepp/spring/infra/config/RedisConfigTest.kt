package com.grepp.spring.infra.config

import com.grepp.spring.infra.event.Outbox
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.data.redis.core.RedisTemplate

@SpringBootTest
class RedisConfigTest{

    @Autowired
    lateinit var redisTemplate: RedisTemplate<String, String>

    @Test
    fun testPub(){
        val outbox = Outbox(
            eventType = "signup_complete",
            payload = "azimemory@gmail.com"
        )
        redisTemplate.convertAndSend("user-service", outbox)
    }
}