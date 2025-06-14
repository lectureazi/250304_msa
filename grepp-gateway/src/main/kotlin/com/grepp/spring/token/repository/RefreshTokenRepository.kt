package com.grepp.spring.token.repository

import com.grepp.spring.token.entity.RefreshToken
import org.springframework.data.repository.CrudRepository

interface RefreshTokenRepository : CrudRepository<RefreshToken, String> {
    fun findByAccessTokenId(id: String): RefreshToken?
    fun deleteByToken(token: String)
}
