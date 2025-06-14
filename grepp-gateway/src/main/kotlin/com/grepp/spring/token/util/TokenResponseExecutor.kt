package com.grepp.spring.token.util

import com.grepp.spring.token.code.TokenType
import com.grepp.spring.token.dto.TokenDto
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.ResponseCookie

class TokenResponseExecutor {
    companion object{
        fun response(
            response: HttpServletResponse,
            tokenDto: TokenDto
        ){
            val accessTokenCookie: ResponseCookie =
                TokenCookieFactory.create(
                    TokenType.ACCESS_TOKEN.name, tokenDto.accessToken,
                    tokenDto.rtExpiresIn
                )

            val refreshTokenCookie: ResponseCookie =
                TokenCookieFactory.create(
                    TokenType.REFRESH_TOKEN.name, tokenDto.refreshToken,
                    tokenDto.rtExpiresIn
                )

            response.addHeader("Set-Cookie", accessTokenCookie.toString())
            response.addHeader("Set-Cookie", refreshTokenCookie.toString())
        }

        fun clear(response: HttpServletResponse) {
            val expiredAccessToken: ResponseCookie =
                TokenCookieFactory.createExpiredToken(TokenType.ACCESS_TOKEN)

            val expiredRefreshToken: ResponseCookie =
                TokenCookieFactory.createExpiredToken(TokenType.REFRESH_TOKEN)

            response.addHeader("Set-Cookie", expiredAccessToken.toString())
            response.addHeader("Set-Cookie", expiredRefreshToken.toString())
        }
    }
}