package com.grepp.auth.app.model.member.entity

import com.grepp.auth.infra.entity.BaseEntity
import jakarta.persistence.Entity
import jakarta.persistence.Id
import java.time.LocalDateTime

@Entity
class MemberInfo(
    @Id
    val userId: String,
    var loginDate: LocalDateTime? = null,
    var modifyDate: LocalDateTime? = null,
    var leaveDate: LocalDateTime? = null,
    var rentableDate: LocalDateTime = LocalDateTime.now()
) : BaseEntity() {

}
