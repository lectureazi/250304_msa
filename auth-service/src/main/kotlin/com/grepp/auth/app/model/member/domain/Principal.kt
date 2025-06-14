package com.grepp.auth.app.model.member.domain

import com.grepp.auth.app.model.member.entity.Member
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User

class Principal(
    private val username: String,
    private val password: String,
    private val authorities: Collection<GrantedAuthority>
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
