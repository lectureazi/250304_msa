package com.grepp.spring.infra.security.oauth2

import com.grepp.spring.token.code.TokenType
import com.grepp.spring.token.service.RefreshTokenService
import com.grepp.spring.token.util.JwtProvider
import com.grepp.spring.token.util.TokenResponseExecutor
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.stereotype.Component

@Component
class OAuth2FailureHandler(
    private val jwtProvider: JwtProvider,
    private val refreshTokenService: RefreshTokenService
): SimpleUrlAuthenticationFailureHandler() {

    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException
    ) {

        val requestAccessToken = jwtProvider.resolveToken(request, TokenType.ACCESS_TOKEN) ?: return
        val claims = jwtProvider.parseClaim(requestAccessToken) ?: return

        refreshTokenService.deleteByAccessTokenId(claims.id)
        TokenResponseExecutor.clear(response)
        redirectStrategy.sendRedirect(request, response, "/")
    }
}