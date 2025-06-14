package com.grepp.spring.infra.event

import com.fasterxml.jackson.databind.ObjectMapper
import com.grepp.spring.app.model.MailService
import com.grepp.spring.app.model.code.MailTemplatePath
import com.grepp.spring.infra.mail.MailTemplate
import com.grepp.spring.infra.mail.SmtpDto
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component


interface MessageDelegate {
    fun handleMessage(message: String)
}

@Component
class EventMessageDelegate(
    private val mailTemplate: MailTemplate,
    private val objectMapper: ObjectMapper
) : MessageDelegate {

    private val log = LoggerFactory.getLogger(javaClass)

    override fun handleMessage(message: String) = runBlocking {
        log.info(message)
        val outbox = objectMapper.readValue(message, OutboxDto::class.java)
        if(outbox.eventType.uppercase() == MailTemplatePath.SIGNUP_COMPLETE.name){
            sendSignupCompleteMail(outbox)
        }
    }

    private suspend fun sendSignupCompleteMail(outbox: OutboxDto) {
        val dto = SmtpDto(
            from = "grepp",
            to = outbox.payload,
            subject = "환영합니다! 고객님",
            templatePath = MailTemplatePath.SIGNUP_COMPLETE.path
        )
        mailTemplate.send(dto)
    }
}