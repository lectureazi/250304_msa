package com.grepp.spring.app.model.member.dto

import java.time.LocalDateTime

data class MemberInfoDto(
    val userId: String,
    val loginDate: LocalDateTime,
    val modifyDate: LocalDateTime,
    val leaveDate: LocalDateTime,
    val rentableDate: LocalDateTime

){

}
