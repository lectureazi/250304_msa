package com.grepp.spring.infra.feign.client

import com.grepp.spring.app.model.member.dto.SmtpDto
import org.springframework.cloud.openfeign.FeignClient
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestHeader

@FeignClient(
    name = "mail-service" // 유레카에 등록된 서비스 이름
)
interface MailApi {
    @PostMapping("/mail/send")
    fun sendMail(
        @RequestHeader(name="x-member-id")
        userId:String = "user-service",
        @RequestHeader(name="x-member-role")
        role:String = "ROLE_SERVER",
        payload:SmtpDto
    ){

    }
}