package com.grepp.spring.infra.event

import org.slf4j.LoggerFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@EnableScheduling
@Service
class OutboxPollingScheduler(
    private val outboxRepository: OutboxRepository,
    private val redisTemplate: RedisTemplate<String, String>
) {

    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional
    @Scheduled(fixedDelayString = "100000000000000")
    fun pollAndPublish(){
        val unpublished = outboxRepository.findByActivatedIsTrueOrderByCreatedAt()
        if(unpublished.isEmpty()) return

        log.info("{}", unpublished)

        unpublished.forEach {
            redisTemplate.convertAndSend("user-service", it)
            it.unActivated()
        }
    }


}