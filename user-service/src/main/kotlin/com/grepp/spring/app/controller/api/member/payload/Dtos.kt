package com.grepp.spring.app.controller.api.member.payload

import com.grepp.spring.infra.annotation.NoArgsConstructor
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank

data class SignupRequest(
    @NotBlank
    val userId:String,
    @NotBlank
    val password:String,
    @Email
    val email:String,
    @NotBlank
    val tel: String
)

@NoArgsConstructor
data class MemberDetailResponse(
    var userId:String,
    var email:String,
    var tel: String
)

