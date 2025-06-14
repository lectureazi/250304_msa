package com.grepp.spring.token.filter

import com.grepp.spring.infra.error.exceptions.CommonException
import com.grepp.spring.infra.response.ResponseCode
import com.grepp.spring.token.code.GrantType
import com.grepp.spring.token.code.TokenType
import com.grepp.spring.token.util.JwtProvider
import com.grepp.spring.token.util.TokenCookieFactory
import com.grepp.spring.token.dto.AccessTokenDto
import com.grepp.spring.token.dto.TokenDto
import com.grepp.spring.token.entity.RefreshToken
import com.grepp.spring.token.entity.UserBlackList
import com.grepp.spring.token.repository.UserBlackListRepository
import com.grepp.spring.token.service.RefreshTokenService
import com.grepp.spring.token.util.TokenResponseExecutor
import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseCookie
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException

@Component
class JwtAuthenticationFilter(
    val jwtProvider: JwtProvider,
    val refreshTokenService: RefreshTokenService,
    val userBlackListRepository: UserBlackListRepository
) : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(javaClass)

    @Throws(ServletException::class)
    protected override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val excludePath: MutableList<String> = ArrayList()
        excludePath.addAll(listOf("/error", "/favicon.ico", "/css", "/img", "/js", "/download"))
        excludePath.addAll(listOf("/member/signup", "/member/signin"))
        val path = request.requestURI
        return excludePath.stream().anyMatch { prefix: String? ->
            path.startsWith(
                prefix!!
            )
        }
    }

    @Throws(ServletException::class, IOException::class)
    protected override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        log.info(request.requestURI)
        val requestAccessToken = jwtProvider.resolveToken(request, TokenType.ACCESS_TOKEN)

        if(requestAccessToken == null) {
            filterChain.doFilter(request, response)
            return
        }

        val claims = jwtProvider.parseClaim(requestAccessToken)
        if (claims == null) {
            filterChain.doFilter(request, response)
            return
        }

        if (userBlackListRepository.existsById(claims.subject)) {
            filterChain.doFilter(request, response)
            return
        }

        try {
            if (jwtProvider.validateToken(requestAccessToken)) {
                request.setAttribute("x-member-id", claims.subject)
                request.setAttribute("x-member-role", claims["roles"])
            }
        } catch (ex: ExpiredJwtException) {
            val newAccessToken: AccessTokenDto? = renewingAccessToken(requestAccessToken, request)
            newAccessToken ?: return

            val newRefreshToken = renewingRefreshToken(claims.id, newAccessToken.id)
            request.setAttribute("x-member-id", claims.subject)
            request.setAttribute("x-member-role", claims["roles"])
            responseToken(response, newAccessToken, newRefreshToken)
        } finally {
            filterChain.doFilter(request, response)
        }
    }

    private fun responseToken(
        response: HttpServletResponse, newAccessToken: AccessTokenDto,
        newRefreshToken: RefreshToken
    ) {
        val tokenDto = TokenDto(
            accessToken = newAccessToken.token,
            refreshToken = newRefreshToken.token,
            grantType = GrantType.BEARER,
            atExpiresIn = jwtProvider.atExpiration,
            rtExpiresIn = jwtProvider.rtExpiration
        )

        TokenResponseExecutor.response(response, tokenDto)
    }

    private fun renewingRefreshToken(id: String, newTokenId: String): RefreshToken {
        return refreshTokenService.renewingToken(id, newTokenId)!!
    }

    private fun renewingAccessToken(
        requestAccessToken: String,
        request: HttpServletRequest
    ): AccessTokenDto? {
        val refreshToken: String? = jwtProvider.resolveToken(request, TokenType.REFRESH_TOKEN)

        val claims: Claims = jwtProvider.parseClaim(requestAccessToken)!!

        val storedRefreshToken: RefreshToken =
            refreshTokenService.findByAccessTokenId(claims.id) ?: return null

        if (storedRefreshToken.token != refreshToken) {
            userBlackListRepository.save(UserBlackList(claims.subject))
            throw CommonException(ResponseCode.SECURITY_INCIDENT)
        }

        return jwtProvider.generateAccessToken(claims.subject, claims["roles"].toString())
    }
}
