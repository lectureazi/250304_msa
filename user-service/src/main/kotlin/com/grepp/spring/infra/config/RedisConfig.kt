package com.grepp.spring.infra.config

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.data.redis.connection.RedisStandaloneConfiguration
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.StringRedisSerializer

@Configuration
@EnableRedisRepositories
class RedisConfig {
    @Value("\${spring.data.redis.port}")
    private var port = 0

    @Value("\${spring.data.redis.host}")
    private var host: String = ""

    @Value("\${spring.data.redis.username}")
    private var username: String = ""

    @Value("\${spring.data.redis.password}")
    private var password: String = ""

    @Bean
    fun redisConnectionFactory(): RedisConnectionFactory {
        val configuration: RedisStandaloneConfiguration = RedisStandaloneConfiguration()
        configuration.username = username
        configuration.port = port
        configuration.hostName = host
        configuration.setPassword(password)
        return LettuceConnectionFactory(configuration)
    }

    @Bean
    fun redisTemplate(
        redisConnectionFactory: RedisConnectionFactory,
        objectMapper: ObjectMapper
    ): RedisTemplate<String, String> {
        val redisTemplate = RedisTemplate<String, String>()
        redisTemplate.connectionFactory = redisConnectionFactory
        redisTemplate.keySerializer = StringRedisSerializer()
        redisTemplate.valueSerializer = GenericJackson2JsonRedisSerializer(objectMapper)
        return redisTemplate
    }
}
