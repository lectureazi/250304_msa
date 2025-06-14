package com.grepp.spring.app.model.member

import com.grepp.spring.app.controller.api.member.payload.MemberDetailResponse
import com.grepp.spring.app.controller.api.member.payload.SignupRequest
import com.grepp.spring.app.model.member.code.Role
import com.grepp.spring.app.model.member.dto.SmtpDto
import com.grepp.spring.app.model.member.entity.Member
import com.grepp.spring.app.model.member.entity.MemberInfo
import com.grepp.spring.infra.error.exceptions.CommonException
import com.grepp.spring.infra.event.Outbox
import com.grepp.spring.infra.event.OutboxRepository
import com.grepp.spring.infra.feign.client.MailApi
import com.grepp.spring.infra.response.ResponseCode
import org.modelmapper.ModelMapper
import org.slf4j.LoggerFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
@Transactional(readOnly = true)
class MemberService(
    private val memberRepository: MemberRepository,
    private val passwordEncoder: PasswordEncoder,
    private val mapper: ModelMapper,
    private val mailApi: MailApi,
    private val outboxRepository: OutboxRepository
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional
    fun signup(request:SignupRequest) {
        if(memberRepository.existsById(request.userId))
            throw CommonException(ResponseCode.BAD_REQUEST)

        val encodedPassword = passwordEncoder.encode(request.password)

        val member = Member(request.userId, encodedPassword,
            request.email, Role.ROLE_USER, request.tel)

        val memberInfo = MemberInfo(request.userId)
        member.info = memberInfo
        memberRepository.save(member)

        val outbox = Outbox(
            eventType = "signup_complete",
            payload = member.email
        )
        outboxRepository.save(outbox)
    }

    fun checkId(id: String): Boolean {
        return memberRepository.existsById(id)
    }

    fun findById(id: String): MemberDetailResponse {
        val member = memberRepository.findById(id)
        return mapper.map(member, MemberDetailResponse::class.java)
    }

    fun verify(token: String, request: SignupRequest) {
        val dto = SmtpDto(
            from = "grepp",
            to = listOf(request.email) ,
            subject = "회원 가입을 완료해주세요.",
            properties = mutableMapOf(
                "token" to token,
                "domain" to "http://localhost:8080"
            ),
            eventType = "signup_verify"
        )

        mailApi.sendMail(payload = dto)
    }
}