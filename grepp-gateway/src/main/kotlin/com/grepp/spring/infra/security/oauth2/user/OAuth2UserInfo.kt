package com.grepp.spring.infra.security.oauth2.user

import org.springframework.security.oauth2.core.user.OAuth2User

interface OAuth2UserInfo {
    val providerId: String
    val provider: String
    val name: String
    val picture: String

    companion object {
        fun create(path: String, user: OAuth2User): OAuth2UserInfo? {
            if (path == "/login/oauth2/code/grepp")
                return GreppOAuth2UserInfo(user.attributes)
            return null
        }
    }
}
