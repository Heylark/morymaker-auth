package kr.co.morymaker.auth.config

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletResponse
import kr.co.morymaker.auth.domain.account.MoryRoles
import kr.co.morymaker.auth.dto.ErrorBody
import kr.co.morymaker.auth.dto.ErrorDetail
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.AccessDeniedHandler

/**
 * §3 어드민 REST 인가 체인(JWT Resource Server 방식) — `/api/accounts` 하위 전체 경로 전용, `@Order(2)`
 * (`@Order(1)` AS 프로토콜 체인과 `@Order(5)` 폼 로그인 catch-all 사이). [SecurityConfig] 미접촉
 * (동결 경계 — 신규 클래스로 분리).
 *
 * ## ⚠️ roles→ROLE_ 컨버터가 이 클래스에서 가장 load-bearing한 부분이다
 * access token `roles` claim은 [TokenCustomizerConfig]가 `ROLE_` 접두사를 제거하고 발급한다
 * (예: `["SYSTEM_ADMIN"]`). [JwtGrantedAuthoritiesConverter]에 `authoritiesClaimName=roles`+
 * `authorityPrefix=ROLE_`를 지정하지 않으면 `hasRole` 판정이 전부 실패해 모든 요청이 403이 된다.
 *
 * ## 요청 레벨 `hasRole` 채택 — 메서드 시큐리티(`@EnableMethodSecurity`) 미도입
 * 4개 엔드포인트가 균일하게 SYSTEM_ADMIN이라 필터 레벨 단일 게이트로 충분하다(YAGNI). 거부는 항상
 * 이 필터체인의 `authenticationEntryPoint`/`accessDeniedHandler` 경로로만 나가므로 401/403 응답
 * envelope이 결정적이다(메서드 시큐리티 예외가 다른 경로로 새어나갈 위험이 없음).
 */
@Configuration
class AdminApiSecurityConfig(
    private val objectMapper: ObjectMapper,
) {

    @Bean
    @Order(2)
    fun adminApiSecurityFilterChain(http: HttpSecurity, jwtDecoder: JwtDecoder): SecurityFilterChain {
        http
            .securityMatcher("/api/accounts/**")
            .authorizeHttpRequests { it.anyRequest().hasRole(MoryRoles.SYSTEM_ADMIN) }
            .oauth2ResourceServer { rs ->
                rs.jwt { jwt -> jwt.decoder(jwtDecoder).jwtAuthenticationConverter(jwtAuthenticationConverter()) }
                rs.authenticationEntryPoint(unauthenticatedEntryPoint())
                rs.accessDeniedHandler(roleForbiddenHandler())
            }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            // stateless Bearer 인증 — ambient 쿠키가 없어 CSRF 공격 표면 자체가 없다(전역 면제가 아닌
            // 이 securityMatcher 범위 안에서만의 국소 비활성화).
            .csrf { it.disable() }
        return http.build()
    }

    /** internal 가시성 — [kr.co.morymaker.auth.config.AdminApiSecurityConfigTest]가 roles→ROLE_ 변환을 직접 검증한다. */
    internal fun jwtAuthenticationConverter(): JwtAuthenticationConverter {
        val authorities = JwtGrantedAuthoritiesConverter().apply {
            setAuthoritiesClaimName("roles")
            setAuthorityPrefix("ROLE_")
        }
        return JwtAuthenticationConverter().apply { setJwtGrantedAuthoritiesConverter(authorities) }
    }

    /** 미인증(토큰 없음·서명 오류·만료) — 401 UNAUTHENTICATED envelope. */
    private fun unauthenticatedEntryPoint() = AuthenticationEntryPoint { _, response, _ ->
        writeError(response, HttpServletResponse.SC_UNAUTHORIZED, "UNAUTHENTICATED", "인증이 필요합니다")
    }

    /** 인증은 됐으나 SYSTEM_ADMIN이 아님 — 403 ROLE_FORBIDDEN envelope. */
    private fun roleForbiddenHandler() = AccessDeniedHandler { _, response, _ ->
        writeError(response, HttpServletResponse.SC_FORBIDDEN, "ROLE_FORBIDDEN", "접근 권한이 없습니다")
    }

    private fun writeError(response: HttpServletResponse, status: Int, code: String, message: String) {
        response.status = status
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.characterEncoding = "UTF-8"
        response.writer.write(objectMapper.writeValueAsString(ErrorBody(ErrorDetail(code, message))))
    }
}
