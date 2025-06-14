package com.grepp.spring.app.model.member.entity

import com.grepp.spring.app.model.member.code.Role
import com.grepp.spring.infra.entity.BaseEntity
import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
class Member(
    @Id
    val userId: String,
    val password: String,
    val email: String,

    @Enumerated(EnumType.STRING)
    val role: Role,
    val tel: String,

    @OneToOne(cascade = [CascadeType.PERSIST, CascadeType.MERGE])
    @JoinColumn(name = "userId")
    var info: MemberInfo? = null,
) : BaseEntity() {

    fun updateLoginedAt(time: LocalDateTime) {
        info?.let{
            it.loginDate=time
        }
    }
}
