package com.grepp.spring.infra.security.domain

import com.grepp.spring.app.model.member.entity.Member
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User

class Principal(
    username: String?,
    password: String?,
    authorities: Collection<GrantedAuthority>
) : User(username, password, authorities) {

    companion object {
        fun createPrincipal(
            member: Member,
            authorities: List<SimpleGrantedAuthority>
        ): Principal {
            return Principal(member.userId, member.password, authorities)
        }
    }
}
