package com.grepp.spring.app.model.member.dto

import com.grepp.spring.app.model.member.code.Role

data class MemberDto(
     val userId: String,
     val password: String,
     val email: String,
     val role: Role,
     val tel: String,
     val info: MemberInfoDto,
) {

}
