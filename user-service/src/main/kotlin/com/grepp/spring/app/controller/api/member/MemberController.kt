package com.grepp.spring.app.controller.api.member

import com.grepp.spring.app.controller.api.member.payload.MemberDetailResponse
import com.grepp.spring.app.controller.api.member.payload.SignupRequest
import com.grepp.spring.app.model.member.MemberService
import com.grepp.spring.infra.response.ApiResponse
import jakarta.servlet.http.HttpSession
import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("api/member")
class MemberController(
    private val memberService: MemberService
) {

    @GetMapping("add/{token}")
    fun signup(
        @PathVariable
        token:String,
        session:HttpSession
    ):ResponseEntity<ApiResponse<Unit>>{
        val request = session.getAttribute(token) as SignupRequest
        memberService.signup(request)
        return ResponseEntity.ok(ApiResponse.noContent())
    }

    @PostMapping("verify")
    fun verify(
        @Valid
        request:SignupRequest,
        session:HttpSession
    ):ResponseEntity<ApiResponse<Unit>>{
        val token = session.id
        session.setAttribute(token, request)
        memberService.verify(token, request)
        return ResponseEntity.ok(ApiResponse.noContent());
    }

    @GetMapping("exists/{id}")
    fun checkDuplicated(
        @PathVariable
        id:String):ResponseEntity<ApiResponse<Boolean>>{
        return ResponseEntity.ok(ApiResponse.success(memberService.checkId(id)))
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("{id}")
    fun get(
        @PathVariable
        id:String
    ):ResponseEntity<ApiResponse<MemberDetailResponse>>{
        val res = memberService.findById(id)
        return ResponseEntity.ok(ApiResponse.success(res))
    }
}