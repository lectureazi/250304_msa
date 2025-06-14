package com.grepp.spring.infra.security

import com.grepp.spring.app.model.member.MemberRepository
import com.grepp.spring.app.model.member.entity.Member
import com.grepp.spring.infra.security.domain.Principal
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.function.Supplier

@Service
@Transactional(readOnly = true)
class UserDetailsServiceImpl(
    private val memberRepository: MemberRepository
) : UserDetailsService {

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails {
        val member: Member = memberRepository.findById(username)
            .orElseThrow<UsernameNotFoundException>(Supplier<UsernameNotFoundException> {
                UsernameNotFoundException(
                    username
                )
            })
        return Principal.createPrincipal(member, listOf(SimpleGrantedAuthority(member.role.name)))
    }

    fun findAuthorities(username: String): MutableSet<SimpleGrantedAuthority> {
        val member = memberRepository.findById(username)
            .orElseThrow {
                UsernameNotFoundException(
                    username
                )
            }
        val authorities: MutableList<SimpleGrantedAuthority> = ArrayList()
        authorities.add(SimpleGrantedAuthority(member.role.name))
        return authorities.toMutableSet()
    }
}
