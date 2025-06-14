package com.grepp.auth.app.model.member

import com.grepp.auth.app.model.member.entity.Member
import org.springframework.data.jpa.repository.JpaRepository

interface MemberRepository:JpaRepository<Member, String> {



}