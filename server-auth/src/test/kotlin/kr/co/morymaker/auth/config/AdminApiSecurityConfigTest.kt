package kr.co.morymaker.auth.config

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.jwt.Jwt
import java.time.Instant

/**
 * [AdminApiSecurityConfig] 단위 테스트 — E3의 가장 load-bearing한 부분(roles→ROLE_ 컨버터)을
 * Spring 컨텍스트 없이 직접 검증한다. 이 변환이 누락되면 `hasRole` 판정이 전부 실패해 SYSTEM_ADMIN도
 * 403을 받는다(02-architect §7 명시 리스크).
 */
class AdminApiSecurityConfigTest {

    private val sut = AdminApiSecurityConfig(objectMapper = ObjectMapper())

    private fun jwtWithClaim(name: String, value: Any): Jwt =
        Jwt.withTokenValue("test-token")
            .header("alg", "RS256")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(3600))
            .subject("acc-1")
            .claim(name, value)
            .build()

    @Test
    fun `roles claim 의 SYSTEM_ADMIN 은 ROLE_SYSTEM_ADMIN authority 로 변환된다`() {
        val converter = sut.jwtAuthenticationConverter()

        val token = converter.convert(jwtWithClaim("roles", listOf("SYSTEM_ADMIN")))

        val authorities = token!!.authorities.map { it.authority }
        assertTrue(authorities.contains("ROLE_SYSTEM_ADMIN"))
    }

    @Test
    fun `roles claim 이 비어있으면 authority 가 없다 (인가 거부로 이어짐)`() {
        val converter = sut.jwtAuthenticationConverter()

        val token = converter.convert(jwtWithClaim("roles", emptyList<String>()))

        assertTrue(token!!.authorities.isEmpty())
    }

    @Test
    fun `authorities claim(잘못된 이름)은 무시된다 -- roles claim 만 인가에 반영돼야 한다`() {
        val converter = sut.jwtAuthenticationConverter()

        val token = converter.convert(jwtWithClaim("authorities", listOf("SYSTEM_ADMIN")))

        assertTrue(token!!.authorities.isEmpty())
    }
}
