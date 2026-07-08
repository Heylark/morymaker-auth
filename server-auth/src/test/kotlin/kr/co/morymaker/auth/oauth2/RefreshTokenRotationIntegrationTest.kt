package kr.co.morymaker.auth.oauth2

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import kr.co.morymaker.auth.config.AuthProperties
import kr.co.morymaker.auth.util.RefreshTokenHashUtil
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
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
 * refresh token rotation 실 HTTP 통합 테스트 — `reuseRefreshTokens=false` 미지정 시 SAS가
 * at-rest 해시를 그대로 재사용해 2차 refresh가 깨지는 회귀를 잠근다.
 * `RegisteredClientSeeder`가 실제로 등록한 web 클라이언트를 대상으로 실 `/oauth2/authorize`·
 * `/oauth2/token` 엔드포인트를 통해 2연속 rotation을 검증한다.
 *
 * ## 왜 mock이 아닌 실 HTTP 흐름인가
 * `HashedRefreshTokenAuthorizationServiceReuseDetectionTest`(mockk 단위 테스트)는 delegate를
 * 스텁으로 대체해 "reuseRefreshTokens=false일 때 SAS가 하는 동작"을 직접 가정하고 구성한다 —
 * 즉 실제 SAS `OAuth2RefreshTokenAuthenticationProvider`가 `RegisteredClient.tokenSettings`를
 * 읽어 rotation 여부를 결정하는 상호작용 자체는 재현하지 못한다. 2차 refresh rotation 실패가
 * 바로 이 상호작용의 결함이었고 mock 기반 단위 테스트를 전부 통과하면서도 실 curl로만 드러났다 —
 * 이 테스트는 그 재발을 실 `/oauth2/token` 호출로 잠근다.
 *
 * ## 세션 유지 전략
 * `MockHttpSession`을 직접 생성해 로그인(POST `/login`)과 인가(GET `/oauth2/authorize`) 두 요청에
 * 동일 인스턴스를 전달한다 — Spring Security의 세션 고정 보호(`changeSessionId`)가 내부적으로 ID를
 * 바꿔도 같은 Java 객체 참조를 재사용하므로 인증 상태가 유지된다. `/oauth2/token`은 클라이언트
 * 인증(Basic clientId:secret)만으로 동작하는 별도 요청이라 세션이 필요 없다.
 *
 * ## `@Transactional`
 * 이 테스트가 시딩한 계정 행은 종료 시 자동 롤백된다(LoginFlowIntegrationTest와 동일 컨벤션).
 * 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class RefreshTokenRotationIntegrationTest {

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

    private val hex64 = Regex("^[0-9a-f]{64}$")

    // ── 계정 시딩 ────────────────────────────────────────────────────────────

    private fun seedAccount(email: String, rawPassword: String): String {
        val id = UUID.randomUUID().toString()
        jdbcTemplate.update(
            """
            INSERT INTO account
                (id, email, name, role, password_hash, failed_attempts, locked_at, locked_until, status, created_at)
            VALUES (?, ?, ?, 'EVENT_ADMIN', ?, 0, NULL, NULL, '활성', ?)
            """.trimIndent(),
            id,
            email,
            "테스트 계정",
            passwordEncoder.encode(rawPassword),
            Timestamp.from(Instant.now()),
        )
        return id
    }

    // ── PKCE ─────────────────────────────────────────────────────────────────

    /** RFC 7636 §4.1 — 43~128자 unreserved 문자 code_verifier. */
    private fun randomCodeVerifier(): String {
        val bytes = ByteArray(64)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /** RFC 7636 §4.2 — S256: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))). */
    private fun codeChallengeS256(codeVerifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(codeVerifier.toByteArray(StandardCharsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    // ── OAuth2 흐름 헬퍼 ─────────────────────────────────────────────────────

    /** 폼 로그인 — 세션에 인증 상태를 심는다(CSRF 활성 — `.with(csrf())` 필수). */
    private fun login(session: MockHttpSession, email: String, rawPassword: String) {
        mockMvc.perform(
            post("/login")
                .session(session)
                .with(csrf())
                .param("username", email)
                .param("password", rawPassword),
        ).andExpect(status().is3xxRedirection)
    }

    /**
     * 인가 코드 발급 — `requireAuthorizationConsent(false)`(RegisteredClientSeeder)라 동의 화면 없이
     * 곧바로 client redirect_uri로 302 + `code` 파라미터가 돌아온다.
     */
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

        val location = result.response.getHeader("Location")
            ?: error("authorize 응답에 Location 헤더 없음")
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

    /** grant_type=refresh_token 요청 — 응답 상태를 검사자가 직접 단언할 수 있도록 raw 응답을 반환한다. */
    private fun requestRefresh(refreshToken: String): org.springframework.test.web.servlet.MvcResult =
        mockMvc.perform(
            post("/oauth2/token")
                .header(HttpHeaders.AUTHORIZATION, clientBasicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "refresh_token")
                .param("refresh_token", refreshToken),
        ).andReturn()

    private fun refreshTokens(refreshToken: String): JsonNode {
        val result = requestRefresh(refreshToken)
        assertEquals(200, result.response.status, "refresh 실패 — 응답: ${result.response.contentAsString}")
        return objectMapper.readTree(result.response.contentAsString)
    }

    // ── TC ───────────────────────────────────────────────────────────────────

    /**
     * refresh 2차 rotation 회귀 가드 — 2연속 rotation이 모두 성공하고, 매 rotation마다 반환되는
     * refresh_token이 진짜 opaque 토큰(64자 hex 해시 형식이 아님)이며, 재사용 탐지 스택이
     * 실제로 활성화(consumed_refresh_tokens 기록 발생)됨을 실 HTTP 흐름으로 증명한다.
     */
    @Test
    fun `2연속 refresh rotation이 모두 성공하고 매번 새 opaque 토큰이 발급되며 consumed 기록이 남는다`() {
        val email = "rotation-${UUID.randomUUID().toString().take(8)}@morymaker.co.kr"
        val rawPassword = "correct-horse-battery-staple"
        seedAccount(email, rawPassword)

        val redirectUri = authProperties.webClient.redirectUris.split(",").first().trim()
        val codeVerifier = randomCodeVerifier()
        val codeChallenge = codeChallengeS256(codeVerifier)

        val session = MockHttpSession()
        login(session, email, rawPassword)
        val code = authorize(session, redirectUri, codeChallenge)

        // 1. authorization_code 교환 → RT0
        val initialTokens = exchangeAuthorizationCode(code, redirectUri, codeVerifier)
        val rt0 = initialTokens.get("refresh_token")?.asText()
        assertNotNull(rt0, "authorization_code 교환 응답에 refresh_token 없음")
        assertFalse(hex64.matches(rt0!!), "RT0는 SAS가 발급한 raw 토큰이어야 함(해시 형식 아님)")

        // 2. 1차 rotation: RT0 → RT1
        val firstRotation = refreshTokens(rt0)
        val rt1 = firstRotation.get("refresh_token")?.asText()
        assertNotNull(rt1, "1차 rotation 응답에 refresh_token 없음")
        assertFalse(
            hex64.matches(rt1!!),
            "★ 핵심 회귀 가드: RT1이 64자 hex(at-rest 해시 형식)와 일치하면 안 됨 — " +
                "reuseRefreshTokens=true로 되돌아가 SAS가 저장된 해시를 그대로 반환하는 2차 rotation 실패 회귀 재발",
        )
        assertFalse(rt1 == rt0, "RT1은 RT0와 달라야 함(진짜 rotation)")

        // consumed_refresh_tokens에 RT0 해시가 기록됐는지 확인 (재사용 탐지 활성 증명)
        val rt0Hash = RefreshTokenHashUtil.hash(rt0)
        val rt0ConsumedCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM consumed_refresh_tokens WHERE token_hash = ?",
            Int::class.java,
            rt0Hash,
        ) ?: 0
        assert(rt0ConsumedCount >= 1) {
            "1차 rotation 후 consumed_refresh_tokens에 RT0 해시 기록이 있어야 함(재사용 탐지 활성 증명) — " +
                "0건이면 reuseRefreshTokens=true로 인해 oldHash==incomingHash가 되어 死코드 상태로 회귀"
        }

        // 3. 2차 rotation: RT1 → RT2 (2연속 rotation 성공 확인)
        val secondRotation = refreshTokens(rt1)
        val rt2 = secondRotation.get("refresh_token")?.asText()
        assertNotNull(rt2, "2차 rotation 응답에 refresh_token 없음")
        assertFalse(
            hex64.matches(rt2!!),
            "★ 핵심 회귀 가드: RT2도 64자 hex와 일치하면 안 됨(2차 rotation도 진짜 opaque 토큰이어야 함)",
        )
        assertFalse(rt2 == rt1, "RT2는 RT1과 달라야 함(진짜 rotation)")

        val rt1Hash = RefreshTokenHashUtil.hash(rt1)
        val rt1ConsumedCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM consumed_refresh_tokens WHERE token_hash = ?",
            Int::class.java,
            rt1Hash,
        ) ?: 0
        assert(rt1ConsumedCount >= 1) { "2차 rotation 후 consumed_refresh_tokens에 RT1 해시 기록이 있어야 함" }

        val totalConsumedCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM consumed_refresh_tokens",
            Int::class.java,
        ) ?: 0
        assert(totalConsumedCount >= 2) { "2연속 rotation 후 consumed_refresh_tokens에 최소 2건이 기록돼야 함" }
    }

    /**
     * (선택 강화) 이미 소비된 refresh 토큰을 grace(30초) 초과 후 재제시하면 invalid_grant + 패밀리
     * 전체(rotation으로 발급된 최신 토큰 포함) 무효화 — refresh 재사용 탐지가 실 `/oauth2/token` 경로에서도
     * 동작함을 증명한다(HashedRefreshTokenAuthorizationServiceReuseDetectionTest는 mock delegate라
     * 실 SAS 엔드포인트 경로를 타지 않는다).
     */
    @Test
    fun `소비된 refresh 토큰을 grace 초과 후 재제시하면 invalid_grant 이며 패밀리 전체가 무효화된다`() {
        val email = "rotation-reuse-${UUID.randomUUID().toString().take(8)}@morymaker.co.kr"
        val rawPassword = "correct-horse-battery-staple"
        seedAccount(email, rawPassword)

        val redirectUri = authProperties.webClient.redirectUris.split(",").first().trim()
        val codeVerifier = randomCodeVerifier()
        val codeChallenge = codeChallengeS256(codeVerifier)

        val session = MockHttpSession()
        login(session, email, rawPassword)
        val code = authorize(session, redirectUri, codeChallenge)

        val initialTokens = exchangeAuthorizationCode(code, redirectUri, codeVerifier)
        val rt0 = initialTokens.get("refresh_token")!!.asText()

        // rotation → RT0 소비, RT1 발급
        val rotation = refreshTokens(rt0)
        val rt1 = rotation.get("refresh_token")!!.asText()

        // consumed_at을 grace(30초) 초과 과거로 직접 조정 — 실 운영에서는 시간 경과로 자연히 발생.
        val rt0Hash = RefreshTokenHashUtil.hash(rt0)
        jdbcTemplate.update(
            "UPDATE consumed_refresh_tokens SET consumed_at = ? WHERE token_hash = ?",
            Timestamp.from(Instant.now().minusSeconds(60)),
            rt0Hash,
        )

        // RT0 재제시 — grace 초과 재사용 탐지 → invalid_grant
        val replay = requestRefresh(rt0)
        assertEquals(
            400,
            replay.response.status,
            "소비된 RT0 재제시는 invalid_grant(400)여야 함 — 응답: ${replay.response.contentAsString}",
        )

        // 패밀리 전체 무효화 확인 — 현재 유효했던 RT1도 이제 조회 불가(invalid_grant)여야 함
        val rt1AfterFamilyKill = requestRefresh(rt1)
        assertEquals(
            400,
            rt1AfterFamilyKill.response.status,
            "family kill 후에는 rotation으로 발급된 RT1도 무효화돼야 함 — 응답: ${rt1AfterFamilyKill.response.contentAsString}",
        )
    }
}
