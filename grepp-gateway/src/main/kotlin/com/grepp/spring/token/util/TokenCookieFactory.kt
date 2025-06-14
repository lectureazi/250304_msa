package com.grepp.spring.token.util

import com.grepp.spring.token.code.TokenType
import org.springframework.http.ResponseCookie

object TokenCookieFactory {
    fun create(name: String, value: String, expires: Long): ResponseCookie {
        return ResponseCookie.from(name, value)
            .httpOnly(true)
            .maxAge(expires) // todo : 배포 후 true 로 변경
            .secure(false)
            .path("/")
            .build()
    }

    fun createExpiredToken(tokenType: TokenType): ResponseCookie {
        return ResponseCookie.from(tokenType.name, "")
            .httpOnly(true)
            .maxAge(0)
            .secure(false)
            .path("/")
            .build()
    }
}
