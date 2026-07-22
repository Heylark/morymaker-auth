package kr.co.morymaker.auth.oauth2

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import kr.co.morymaker.auth.config.AuthProperties
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.util.UriComponentsBuilder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.sql.Timestamp
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * REQ-0045 — RP-initiated logout(`/connect/logout`) 실 HTTP 통합 검증(설계 §5 V6·V7).
 *
 * V6: 등록된 post_logout_redirect_uri는 byte-exact로만 통과한다(끝 슬래시 하나로도 거부).
 * V7: refresh 1회 후 옛 id_token_hint는 거부되고(회전 누락 확인용 대조군 — B1의 web측 회전
 *     자체를 검증하지 않는다, 그건 web 레포 V8/V8-a/V8-b의 몫), 새 id_token_hint는 통과한다.
 *     (Architect 설계 v2는 이 항목을 "auth 특성화 테스트"로 재분류해 B1 가드 목록에서 뺐지만,
 *     Manager 검증 스코프가 "실측 재현"을 P1 필수로 명시했으므로 이 파일에서 실행한다.)
 *
 * 세션·PKCE 헬퍼는 [RefreshTokenRotationIntegrationTest]와 동일 패턴(중복 작성 — 그 파일의
 * private 헬퍼를 이 파일에서 재사용할 경로가 없어 테스트 코드 범위에서 복제한다).
 *
 * 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class LogoutFlowIntegrationTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var objectMapper: ObjectMapper

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

    private fun randomCodeVerifier(): String {
        val bytes = ByteArray(64)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun codeChallengeS256(codeVerifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(codeVerifier.toByteArray(StandardCharsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    private fun login(session: MockHttpSession, email: String, rawPassword: String) {
        mockMvc.perform(
            post("/login")
                .session(session)
                .with(csrf())
                .param("username", email)
                .param("password", rawPassword),
        ).andExpect(status().is3xxRedirection)
    }

    private fun authorize(session: MockHttpSession, redirectUri: String, codeChallenge: String): String {
        val uri = UriComponentsBuilder.fromPath("/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", authProperties.webClient.clientId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("scope", "openid")
            .queryParam("code_challenge", codeChallenge)
            .queryParam("code_challenge_method", "S256")
            .build()
            .encode()
            .toUri()

        val result = mockMvc.perform(get(uri).session(session))
            .andExpect(status().is3xxRedirection)
            .andReturn()

        val location = result.response.getHeader("Location") ?: error("authorize 응답에 Location 헤더 없음")
        val code = UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("code")
        assertNotNull(code, "authorize redirect에 code 파라미터 없음 — location=$location")
        return code!!
    }

    private fun clientBasicAuthHeader(): String =
        "Basic " + Base64.getEncoder().encodeToString(
            "${authProperties.webClient.clientId}:${authProperties.webClient.clientSecret}".toByteArray(),
        )

    private fun exchangeAuthorizationCode(code: String, redirectUri: String, codeVerifier: String): JsonNode {
        val result = mockMvc.perform(
            post("/oauth2/token")
                .header(HttpHeaders.AUTHORIZATION, clientBasicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", redirectUri)
                .param("code_verifier", codeVerifier),
        )
            .andExpect(status().isOk)
            .andReturn()
        return objectMapper.readTree(result.response.contentAsString)
    }

    private fun refreshTokens(refreshToken: String): JsonNode {
        val result = mockMvc.perform(
            post("/oauth2/token")
                .header(HttpHeaders.AUTHORIZATION, clientBasicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "refresh_token")
                .param("refresh_token", refreshToken),
        ).andReturn()
        assertEquals(200, result.response.status, "refresh 실패 — 응답: ${result.response.contentAsString}")
        return objectMapper.readTree(result.response.contentAsString)
    }

    /** 로그인→authorize→code 교환까지 완주해 신선한 id_token/refresh_token 쌍을 만든다. */
    private fun freshTokenSet(): JsonNode = freshTokenSetWithContext().tokens

    /**
     * [freshTokenSet]과 동일하게 완주하되, 뒤이어 같은 세션으로 재요청(예: 실패한 로그아웃 이후
     * IdP 세션 생존 확인)이 필요한 테스트를 위해 세션·redirect_uri도 함께 반환한다.
     */
    private data class TokenContext(val tokens: JsonNode, val session: MockHttpSession, val redirectUri: String)

    private fun freshTokenSetWithContext(): TokenContext {
        val email = "logout-${UUID.randomUUID().toString().take(8)}@morymaker.co.kr"
        val rawPassword = "correct-horse-battery-staple"
        seedAccount(email, rawPassword)

        val redirectUri = authProperties.webClient.redirectUris.split(",").first().trim()
        val codeVerifier = randomCodeVerifier()
        val codeChallenge = codeChallengeS256(codeVerifier)

        val session = MockHttpSession()
        login(session, email, rawPassword)
        val code = authorize(session, redirectUri, codeChallenge)
        val tokens = exchangeAuthorizationCode(code, redirectUri, codeVerifier)
        return TokenContext(tokens, session, redirectUri)
    }

    private fun connectLogout(
        idTokenHint: String,
        postLogoutRedirectUri: String?,
        session: MockHttpSession? = null,
    ): org.springframework.test.web.servlet.MvcResult {
        val builder = UriComponentsBuilder.fromPath("/connect/logout")
            .queryParam("id_token_hint", idTokenHint)
        if (postLogoutRedirectUri != null) {
            builder.queryParam("post_logout_redirect_uri", postLogoutRedirectUri)
        }
        var request = get(builder.build().encode().toUri())
        if (session != null) {
            request = request.session(session)
        }
        return mockMvc.perform(request).andReturn()
    }

    // ── V6 ──────────────────────────────────────────────────────────────────

    @Test
    fun `V6 - 등록된 post_logout_redirect_uri 그대로 요청하면 302로 그 URI에 착지한다`() {
        val tokens = freshTokenSet()
        val idToken = tokens.get("id_token")!!.asText()
        val registeredUri = authProperties.webClient.postLogoutRedirectUris.split(",").first().trim()

        val result = connectLogout(idToken, registeredUri)
        assertEquals(302, result.response.status, "등록값 그대로는 302여야 함 — 응답: ${result.response.contentAsString}")
        assertEquals(registeredUri, result.response.getHeader("Location"))
    }

    @Test
    fun `V6 - 등록값에 슬래시 하나만 추가해도 post_logout_redirect_uri 불일치로 400이다`() {
        val tokens = freshTokenSet()
        val idToken = tokens.get("id_token")!!.asText()
        val registeredUri = authProperties.webClient.postLogoutRedirectUris.split(",").first().trim()
        val unregisteredUri = "$registeredUri/"

        val result = connectLogout(idToken, unregisteredUri)
        assertEquals(
            400,
            result.response.status,
            "★ 핵심 회귀 가드: byte-exact 미일치(끝 슬래시 하나)는 400이어야 함(Set.contains=String.equals, §1-G) — " +
                "실제 status=${result.response.status}, 응답=${result.response.contentAsString}",
        )
    }

    /**
     * V6-보강 — Tester 확증 공백 2 보완. 기존 V6/V7은 400 자체만 단언하고 그 이후 IdP 세션이
     * 살아있는지는 검증하지 않았다(어떤 TC도 400 이후 세션 상태를 재확인하지 않음). SAS의
     * [org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationProvider]는
     * 검증 실패 시 예외만 던지고 [org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler]를
     * 호출하지 않으므로(성공 분기에서만 실행) 이론상 세션은 살아있어야 한다 — 이 테스트가 그 이론을
     * 실제 HTTP 왕복으로 확인한다. 같은 세션으로 재개하는 authorize가 /login으로 튕기지 않고
     * 곧바로 새 인가 코드를 발급하면(=무마찰 재인가) 세션 생존의 직접 증거다.
     */
    @Test
    fun `V6-보강 - post_logout_redirect_uri 불일치로 400을 받아도 같은 세션의 IdP 로그인 상태는 그대로 살아있다`() {
        val ctx = freshTokenSetWithContext()
        val idToken = ctx.tokens.get("id_token")!!.asText()
        val registeredUri = authProperties.webClient.postLogoutRedirectUris.split(",").first().trim()
        val unregisteredUri = "$registeredUri/"

        val failed = connectLogout(idToken, unregisteredUri, ctx.session)
        assertEquals(
            400,
            failed.response.status,
            "사전조건 실패 — 이 테스트는 400 발생을 전제로 세션 생존을 검증한다(전제 자체가 깨지면 " +
                "아래 단언은 의미가 없음, vacuous 방지)",
        )

        val newCodeVerifier = randomCodeVerifier()
        val newCodeChallenge = codeChallengeS256(newCodeVerifier)
        val uri = UriComponentsBuilder.fromPath("/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", authProperties.webClient.clientId)
            .queryParam("redirect_uri", ctx.redirectUri)
            .queryParam("scope", "openid")
            .queryParam("code_challenge", newCodeChallenge)
            .queryParam("code_challenge_method", "S256")
            .build()
            .encode()
            .toUri()

        val result = mockMvc.perform(get(uri).session(ctx.session)).andReturn()
        val location = result.response.getHeader("Location") ?: ""
        assertTrue(
            !location.contains("/login"),
            "★ 핵심 회귀 가드(확증 공백 2): 실패한 로그아웃(400) 직후에도 세션이 /login으로 튕기면 " +
                "안 됨(세션이 곁다리로 무효화됐다는 뜻 — '웹 쿠키만 지워지고 IdP 세션은 400인 채 " +
                "생존'을 전제로 한 04-test-result.md 판정의 실측 근거) — 실제 status=${result.response.status}, location=$location",
        )
        val code = UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("code")
        assertNotNull(code, "400 이후에도 세션이 살아있다면 authorize가 code를 즉시 재발급해야 함 — location=$location")
    }

    // ── V7 ──────────────────────────────────────────────────────────────────

    @Test
    fun `V7 - refresh 1회 후 옛 id_token_hint는 400, 새 id_token_hint는 302다`() {
        val tokens = freshTokenSet()
        val oldIdToken = tokens.get("id_token")!!.asText()
        val refreshToken = tokens.get("refresh_token")!!.asText()
        val registeredUri = authProperties.webClient.postLogoutRedirectUris.split(",").first().trim()

        val rotated = refreshTokens(refreshToken)
        val newIdToken = rotated.get("id_token")?.asText()
        assertNotNull(newIdToken, "refresh 응답에 id_token이 없음(openid scope 인가 레코드에 새 ID 토큰이 발급돼야 함 — §1-E)")
        assertNotEquals(oldIdToken, newIdToken, "회전 후 id_token은 이전 값과 달라야 함")

        val oldHintResult = connectLogout(oldIdToken, registeredUri)
        assertEquals(
            400,
            oldHintResult.response.status,
            "★ 핵심 회귀 가드(blocker): refresh로 대체된 옛 id_token_hint는 조회되지 않아 400이어야 함(§1-E 검증 순서 1단계) — " +
                "실제 status=${oldHintResult.response.status}",
        )

        val newHintResult = connectLogout(newIdToken!!, registeredUri)
        assertEquals(
            302,
            newHintResult.response.status,
            "새(회전된) id_token_hint는 302로 통과해야 함 — 실제 status=${newHintResult.response.status}, " +
                "응답=${newHintResult.response.contentAsString}",
        )
        assertEquals(registeredUri, newHintResult.response.getHeader("Location"))
    }
}
