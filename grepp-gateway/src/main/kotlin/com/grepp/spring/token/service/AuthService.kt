package com.grepp.spring.token.service

import com.grepp.spring.token.code.GrantType
import com.grepp.spring.token.util.JwtProvider
import com.grepp.spring.token.dto.AccessTokenDto
import com.grepp.spring.token.dto.TokenDto
import com.grepp.spring.token.entity.RefreshToken
import com.grepp.spring.token.repository.UserBlackListRepository
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Duration

@Service
@Transactional(readOnly = true)
class AuthService(
    private val redisTemplate: RedisTemplate<String, Any>,
    val userBlackListRepository: UserBlackListRepository,
    val jwtProvider: JwtProvider
    ) {

    fun processTokenSignin(username: String, roles: String): TokenDto {
        // 블랙리스트에서 제거
        userBlackListRepository.deleteById(username)

        val dto: AccessTokenDto = jwtProvider.generateAccessToken(username, roles)
        val refreshToken = RefreshToken(accessTokenId = dto.id)
        redisTemplate.opsForValue()[dto.id, refreshToken] =  Duration.ofSeconds(refreshToken.ttl)

        return TokenDto(
            accessToken = dto.token,
            refreshToken = refreshToken.token,
            atExpiresIn = jwtProvider.atExpiration,
            rtExpiresIn = jwtProvider.rtExpiration,
            grantType = GrantType.BEARER
        )
    }
}
