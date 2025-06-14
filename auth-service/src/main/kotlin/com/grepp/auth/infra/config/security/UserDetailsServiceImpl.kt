package com.grepp.auth.infra.config.security

import com.grepp.auth.app.model.member.MemberRepository
import com.grepp.auth.app.model.member.domain.Principal
import com.grepp.auth.app.model.member.entity.Member
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
@Transactional(readOnly = true)
class UserDetailsServiceImpl(
    private val memberRepository: MemberRepository
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val member: Member = memberRepository.findById(username)
            .orElseThrow(){UsernameNotFoundException(username)}
        return Principal.createPrincipal(
            member,
            listOf(SimpleGrantedAuthority(member.role.name))
        )
    }
}
