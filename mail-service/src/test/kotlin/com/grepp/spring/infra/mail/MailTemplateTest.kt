package com.grepp.spring.infra.mail

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import kotlin.test.Test

@SpringBootTest
class MailTemplateTest{

    @Autowired
    lateinit var template: MailTemplate

    @Test
    fun testSend() = runBlocking{
        val dto = SmtpDto(
            templatePath = "/mail/signup-verification",
            from = "grepp",
            to = "azimemory@gmail.com",
            subject = "mail test"
        )

        val semaphore = Semaphore(3)
        for(i in  1..3){
            launch(Dispatchers.IO) {
                semaphore.withPermit {
                    template.send(dto)
                }
            }
        }
    }
}