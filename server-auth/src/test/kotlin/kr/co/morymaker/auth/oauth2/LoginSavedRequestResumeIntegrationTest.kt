package kr.co.morymaker.auth.oauth2

import kr.co.morymaker.auth.config.AuthProperties
import org.hamcrest.Matchers.containsString
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

/**
 * 브랜딩 로그인 페이지 도입(커스텀 `loginPage("/login")`) 후 OIDC authorize 재개 경로 검증.
 *
 * `loginPage()` 커스터마이징은 success handler를 바꾸지 않으므로 기본
 * `SavedRequestAwareAuthenticationSuccessHandler`가 그대로 로그인 성공 후 원래 요청(`/oauth2/authorize`)으로
 * 재개해야 한다 — 이 재개 경로는 기존 `RefreshTokenRotationIntegrationTest`가 커버하지 못한다(그 테스트는
 * 로그인부터 먼저 완료한 뒤 authorize를 별도 요청으로 수행해 SavedRequest 자체가 생성되지 않는다).
 * 이 테스트는 반대 순서(미인증 authorize 진입 → 로그인)로 실제 재개 메커니즘을 실 HTTP 흐름으로 증명한다.
 *
 * 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다(다른 `@SpringBootTest` 클래스와 동일 전제).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class LoginSavedRequestResumeIntegrationTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var jdbcTemplate: JdbcTemplate

    @Autowired
    private lateinit var authProperties: AuthProperties

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    private fun seedAccount(email: String, rawPassword: String) {
        jdbcTemplate.update(
            """
            INSERT INTO account
                (id, email, name, role, password_hash, failed_attempts, locked_at, locked_until, status, created_at)
            VALUES (?, ?, ?, 'EVENT_ADMIN', ?, 0, NULL, NULL, '활성', ?)
            """.trimIndent(),
            UUID.randomUUID().toString(),
            email,
            "테스트 계정",
            passwordEncoder.encode(rawPassword),
            Timestamp.from(Instant.now()),
        )
    }

    /** RegisteredClientSeeder가 등록한 web 클라이언트를 대상으로 하는 유효 PKCE authorize 요청 URI. */
    private fun authorizeUri(): URI =
        UriComponentsBuilder.fromPath("/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", authProperties.webClient.clientId)
            .queryParam("redirect_uri", authProperties.webClient.redirectUris.split(",").first().trim())
            .queryParam("scope", "openid")
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .queryParam("code_challenge_method", "S256")
            .build()
            .encode()
            .toUri()

    @Test
    fun `미인증 OIDC authorize 진입 후 로그인 성공 시 원래 authorize 요청으로 재개된다`() {
        val session = MockHttpSession()

        // 1. 미인증 상태로 authorize 진입 — @Order(1) 체인이 원 요청을 세션 RequestCache에 저장하고 /login으로 302
        mockMvc.perform(get(authorizeUri()).session(session).header("Accept", MediaType.TEXT_HTML_VALUE))
            .andExpect(status().is3xxRedirection)
            .andExpect(header().string("Location", containsString("/login")))

        // 2. 커스텀 로그인 페이지에서 자격증명 제출 — 같은 세션(두 체인이 HttpSession 공유)
        val email = "resume-${UUID.randomUUID().toString().take(8)}@morymaker.co.kr"
        val rawPassword = "correct-horse-battery-staple"
        seedAccount(email, rawPassword)

        val loginResult = mockMvc.perform(
            post("/login")
                .session(session)
                .with(csrf())
                .param("username", email)
                .param("password", rawPassword),
        ).andExpect(status().is3xxRedirection).andReturn()

        val redirectLocation = loginResult.response.getHeader("Location")
        assertNotNull(redirectLocation, "로그인 성공 응답에 Location 헤더 없음")
        assertTrue(
            redirectLocation!!.contains("/oauth2/authorize"),
            "★ 핵심 회귀 가드: 로그인 성공 후 Location이 /oauth2/authorize를 포함해야 함(SavedRequest 재개) — " +
                "실제 Location=$redirectLocation. loginPage() 커스터마이징이 success handler를 기본값" +
                "(SavedRequestAwareAuthenticationSuccessHandler)에서 벗어나게 했다면 이 재개가 깨진다.",
        )
    }

    @Test
    fun `CSRF 토큰 없는 POST login은 403을 받는다`() {
        // 전역 CSRF 활성 회귀 가드 — 커스텀 로그인 폼 도입이 CSRF 정책을 약화시키지 않았는지 확인.
        mockMvc.perform(
            post("/login")
                .param("username", "csrf-guard@morymaker.co.kr")
                .param("password", "irrelevant"),
        ).andExpect(status().isForbidden)
    }
}
