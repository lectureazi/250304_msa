package com.grepp.spring.token.filter

import com.grepp.spring.token.code.TokenType
import com.grepp.spring.token.util.JwtProvider
import com.grepp.spring.token.util.TokenCookieFactory
import com.grepp.spring.token.service.RefreshTokenService
import io.jsonwebtoken.Claims
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.ResponseCookie
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException

@Component
class GatewayLogoutFilter(
    val jwtProvider: JwtProvider,
    val refreshTokenService: RefreshTokenService
) : OncePerRequestFilter() {
    @Throws(ServletException::class, IOException::class)
    protected override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val accessToken: String? = jwtProvider.resolveToken(request, TokenType.ACCESS_TOKEN)

        if (accessToken == null) {
            filterChain.doFilter(request, response)
            return
        }

        val path = request.requestURI
        val claims = jwtProvider.parseClaim(accessToken)

        if (claims == null) {
            filterChain.doFilter(request, response)
            return
        }

        if (path == "/logout") {
            refreshTokenService.deleteByAccessTokenId(claims.id)
            val expiredAccessToken: ResponseCookie =
                TokenCookieFactory.createExpiredToken(TokenType.ACCESS_TOKEN)
            val expiredRefreshToken: ResponseCookie =
                TokenCookieFactory.createExpiredToken(TokenType.REFRESH_TOKEN)
            val expiredSessionId: ResponseCookie =
                TokenCookieFactory.createExpiredToken(TokenType.AUTH_SERVER_SESSION_ID)
            response.addHeader("Set-Cookie", expiredAccessToken.toString())
            response.addHeader("Set-Cookie", expiredRefreshToken.toString())
            response.addHeader("Set-Cookie", expiredSessionId.toString())
            response.sendRedirect("/")
            filterChain.doFilter(request, response)
            return
        }

        filterChain.doFilter(request, response)
    }
}
