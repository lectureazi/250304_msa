package com.grepp.spring.infra.security.oauth2

import com.grepp.spring.infra.security.oauth2.user.OAuth2UserInfo
import com.grepp.spring.token.repository.UserBlackListRepository
import com.grepp.spring.token.service.AuthService
import com.grepp.spring.token.util.TokenResponseExecutor
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.stereotype.Component

@Component
class OAuth2SuccessHandler(
    private val authService: AuthService,
    private val userBlackListRepository: UserBlackListRepository
) : SimpleUrlAuthenticationSuccessHandler() {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        val path = request.requestURI
        val user = authentication.principal as OAuth2User
        val userInfo = OAuth2UserInfo.create(path, user)

        val roles = user.getAttribute<ArrayList<String>>("roles")?.first()
        val tokenDto = authService.processTokenSignin(userInfo!!.name, roles ?: "ROLE_ANONYMOUS")

        userBlackListRepository.deleteById(userInfo.name)
        TokenResponseExecutor.response(response, tokenDto)
        redirectStrategy.sendRedirect(request,response,"/")
    }
}