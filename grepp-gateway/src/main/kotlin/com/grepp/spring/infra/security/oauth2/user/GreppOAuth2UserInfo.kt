package com.grepp.spring.infra.security.oauth2.user

class GreppOAuth2UserInfo(private val attributes: Map<String, Any>) : OAuth2UserInfo {
    override val providerId: String
        get() = attributes["sub"].toString()

    override val provider: String
        get() = "grepp"

    override val name: String
        get() = attributes["sub"].toString()

    override val picture: String
        get() = ""
}
