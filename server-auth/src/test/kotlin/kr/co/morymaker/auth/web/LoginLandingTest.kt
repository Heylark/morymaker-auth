package kr.co.morymaker.auth.web

import kr.co.morymaker.auth.config.AuthProperties
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.transaction.annotation.Transactional
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

/**
 * REQ-0045 — 직접 로그인 착지 검증(설계 §5 V2·V3).
 *
 * V1(미인증 GET /login → 200 폼)·V4(SavedRequest 존재 시 authorize 재개)는 기존
 * [LoginControllerTest]·[LoginSavedRequestResumeIntegrationTest]가 이미 커버하므로 여기서는
 * 중복 작성하지 않는다 — 이 파일은 그 두 항목이 다루지 못하는 "인증 상태 재접근"과
 * "SavedRequest 부재 직접 로그인 착지"만 다룬다.
 *
 * 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다(다른 @SpringBootTest 클래스와 동일 전제).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class LoginLandingTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var authProperties: AuthProperties

    @Autowired
    private lateinit var jdbcTemplate: JdbcTemplate

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

    /**
     * V2 — 인증 상태에서 GET /login 재접근 시 302 successLandingUrl로 보낸다(폼 재노출 없음).
     * 되돌리면 RED: LoginController의 익명 fail-open 분기(§2-2)를 제거하면 200 폼이 재노출돼
     * status 단언이 실패한다.
     */
    @Test
    fun `V2 - 인증된 GET login은 successLandingUrl로 302 리다이렉트된다`() {
        mockMvc.perform(get("/login").with(user("v2-authenticated@morymaker.co.kr").roles("EVENT_ADMIN")))
            .andExpect(status().is3xxRedirection)
            .andExpect(header().string("Location", authProperties.webClient.successLandingUrl))
    }

    /**
     * V3 — SavedRequest 부재 상태(사전 authorize 왕복 없이 곧바로 /login에 자격증명을 제출)로
     * 로그인 성공하면 Location이 successLandingUrl과 byte-exact로 일치한다.
     * 되돌리면 RED: SecurityConfig의 `defaultSuccessUrl(...)` 지정을 제거하면 Spring 기본값인
     * `/`로 리다이렉트돼 이 단언이 실패한다(§1-B 실측 재현).
     */
    @Test
    fun `V3 - SavedRequest 부재 직접 로그인은 successLandingUrl로 정확히 리다이렉트된다`() {
        val email = "v3-direct-${UUID.randomUUID().toString().take(8)}@morymaker.co.kr"
        val rawPassword = "correct-horse-battery-staple"
        seedAccount(email, rawPassword)

        // 사전 GET(authorize/login) 없이 새 세션으로 곧바로 POST /login만 수행 — SavedRequest가
        // 세션에 저장될 기회 자체가 없다(§1-B PROBE-B-noSavedRequest와 동일 조건).
        val result = mockMvc.perform(
            post("/login")
                .with(csrf())
                .param("username", email)
                .param("password", rawPassword),
        ).andExpect(status().is3xxRedirection).andReturn()

        val location = result.response.getHeader("Location")
        assertNotNull(location, "로그인 성공 응답에 Location 헤더 없음")
        assertEquals(
            authProperties.webClient.successLandingUrl,
            location,
            "★ 핵심 회귀 가드: SavedRequest 부재 시 Location은 successLandingUrl과 byte-exact로 같아야 함 — " +
                "실제 Location=$location",
        )
        assertTrue(location!!.startsWith("http"), "successLandingUrl은 절대 URL이어야 함(크로스 오리진 착지 — §1-B)")
    }
}
