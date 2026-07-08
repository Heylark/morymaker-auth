package kr.co.morymaker.auth.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.transaction.annotation.Transactional
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

/**
 * event_ids claim 실 DB 통합 테스트 — 계정+account_event를 실제 시딩하고,
 * Spring이 배선한 실 `EventScopePort` 빈(`EventScopePersistenceAdapter` — 실 AccountMapper/AccountEventMapper
 * 조회)을 경유해 access token에 실제로 실리는 claim을 실측한다.
 *
 * `TokenCustomizerConfigTest`(mockk 단위 테스트)는 EventScopePort를 스텁으로 대체해 커스터마이저 로직만
 * 검증하지만, 역할→event_ids 판정이 실 DB 조회 2회(role 조회 → account_event 조회)로 올바르게 이어지는지는
 * 이 통합 테스트로만 검증된다(TASK_LOG Developer Phase 3 완료 기준 "TokenCustomizer 통합 테스트" 요건).
 *
 * `@Transactional`: 각 테스트가 삽입한 계정/매핑 행은 테스트 종료 시 자동 롤백된다(LoginFlowIntegrationTest와
 * 동일 컨벤션) — 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다.
 */
@SpringBootTest
@Transactional
class TokenCustomizerEventIdsIntegrationTest {

    @Autowired
    private lateinit var jdbcTemplate: JdbcTemplate

    @Autowired
    private lateinit var tokenCustomizer: OAuth2TokenCustomizer<JwtEncodingContext>

    private val registeredClient: RegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("test-client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://example.test/callback")
        .scope("openid")
        .build()

    private fun seedAccount(role: String): String {
        val id = UUID.randomUUID().toString()
        jdbcTemplate.update(
            """
            INSERT INTO account
                (id, email, name, role, password_hash, failed_attempts, locked_at, locked_until, status, created_at)
            VALUES (?, ?, ?, ?, ?, 0, NULL, NULL, '활성', ?)
            """.trimIndent(),
            id,
            "$role-${id.take(8)}@morymaker.co.kr",
            "테스트 계정",
            role,
            "{bcrypt-hash}",
            Timestamp.from(Instant.now()),
        )
        return id
    }

    private fun assignEvent(accountId: String, eventId: String) {
        jdbcTemplate.update("INSERT INTO account_event (account_id, event_id) VALUES (?, ?)", accountId, eventId)
    }

    private fun accessTokenContextFor(accountId: String): JwtEncodingContext =
        JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), JwtClaimsSet.builder())
            .registeredClient(registeredClient)
            .principal(
                UsernamePasswordAuthenticationToken(
                    accountId, null, listOf(SimpleGrantedAuthority("ROLE_EVENT_ADMIN")),
                ),
            )
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .build()

    @Test
    fun `SYSTEM_ADMIN 계정은 event_ids 클레임이 부재한다 (전체 허용)`() {
        val id = seedAccount("SYSTEM_ADMIN")
        val context = accessTokenContextFor(id)

        tokenCustomizer.customize(context)

        assertFalse(
            context.claims.build().claims.containsKey("event_ids"),
            "SYSTEM_ADMIN은 event_ids claim 자체가 없어야 함(role 조회 → SYSTEM_ADMIN 분기)",
        )
    }

    @Test
    fun `EVENT_ADMIN 계정은 담당 event_id 배열이 클레임으로 발급된다`() {
        val id = seedAccount("EVENT_ADMIN")
        val eventA = UUID.randomUUID().toString()
        val eventB = UUID.randomUUID().toString()
        assignEvent(id, eventA)
        assignEvent(id, eventB)
        val context = accessTokenContextFor(id)

        tokenCustomizer.customize(context)

        @Suppress("UNCHECKED_CAST")
        val eventIds = context.claims.build().claims["event_ids"] as Collection<String>
        assertEquals(setOf(eventA, eventB), eventIds.toSet())
    }

    @Test
    fun `EVENT_STAFF 계정도 배정된 event_id 배열이 클레임으로 발급된다`() {
        val id = seedAccount("EVENT_STAFF")
        val eventId = UUID.randomUUID().toString()
        assignEvent(id, eventId)
        val context = accessTokenContextFor(id)

        tokenCustomizer.customize(context)

        @Suppress("UNCHECKED_CAST")
        val eventIds = context.claims.build().claims["event_ids"] as Collection<String>
        assertEquals(listOf(eventId), eventIds.toList())
    }

    @Test
    fun `담당 행사가 없는 EVENT_STAFF는 빈 배열이 클레임으로 발급된다 (SYSTEM_ADMIN의 claim 부재와 구분)`() {
        val id = seedAccount("EVENT_STAFF")
        val context = accessTokenContextFor(id)

        tokenCustomizer.customize(context)

        val claims = context.claims.build().claims
        assertTrue(claims.containsKey("event_ids"), "역할은 있으므로 배정이 0건이라도 claim 자체는 존재해야 함")
        @Suppress("UNCHECKED_CAST")
        val eventIds = claims["event_ids"] as Collection<String>
        assertTrue(eventIds.isEmpty(), "배정된 행사가 없으면 빈 배열이어야 함(SYSTEM_ADMIN의 null과 구분)")
    }
}
