package com.grepp.spring.token.dto

import com.grepp.spring.token.code.GrantType

data class AccessTokenDto(
    val id: String,
    val token: String,
    val expiresIn: Long
)

data class TokenDto(
    val accessToken: String,
    val refreshToken: String,
    val grantType: GrantType,
    val atExpiresIn: Long,
    val rtExpiresIn: Long,
)

