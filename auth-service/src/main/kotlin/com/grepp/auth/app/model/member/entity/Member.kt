package com.grepp.auth.app.model.member.entity

import com.grepp.auth.app.model.member.code.Role
import com.grepp.auth.infra.entity.BaseEntity
import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
class Member(
    @Id
    val userId: String,
    var password: String,
    var email: String,

    @Enumerated(EnumType.STRING)
    var role: Role,
    var tel: String,

    @OneToOne(cascade = [CascadeType.PERSIST, CascadeType.MERGE])
    @JoinColumn(name = "userId")
    var info: MemberInfo? = null,
) : BaseEntity() {
    fun updateLoginedAt(time: LocalDateTime?) {
        info?.loginDate = time;
    }
}
