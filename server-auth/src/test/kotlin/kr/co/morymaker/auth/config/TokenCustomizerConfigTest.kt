package kr.co.morymaker.auth.config

import io.mockk.every
import io.mockk.mockk
import kr.co.morymaker.auth.application.port.`in`.account.AccountUseCase
import kr.co.morymaker.auth.application.port.out.event.EventScopePort
import kr.co.morymaker.auth.domain.account.Account
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
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
import java.time.Instant
import java.util.UUID

/**
 * [TokenCustomizerConfig] 단위 테스트 — Spring context 없이 [JwtEncodingContext]를 직접 구성해
 * customizer를 적용한다(빠른 검증, yulse `TokenCustomizerConfigTest` 패턴 재활용).
 *
 * 검증: access token roles/authorities(RBAC B) + event_ids(null=SYSTEM_ADMIN → claim 생략
 * / 빈 배열=배정 0건 → claim은 존재) + ID_TOKEN email claim(scope-gated, AccountUseCase#findById).
 *
 * 실 DB 기반 EventScopePort(EventScopePersistenceAdapter)와의 배선 검증은
 * `TokenCustomizerEventIdsIntegrationTest`(실 MariaDB)가 담당한다 — 이 파일은 커스터마이저 로직만 검증한다.
 */
class TokenCustomizerConfigTest {

    private val noEventScopePort: EventScopePort = mockk<EventScopePort>().also {
        every { it.resolveEventIds(any()) } returns null
    }
    private val noopAccountUseCase: AccountUseCase = mockk(relaxed = true)

    private val customizer = TokenCustomizerConfig(noEventScopePort, noopAccountUseCase).tokenCustomizer()

    private val registeredClient: RegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("test-client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://example.test/callback")
        .scope("openid")
        .build()

    private fun jwsHeaderBuilder(): JwsHeader.Builder = JwsHeader.with(SignatureAlgorithm.RS256)

    private fun accessTokenContext(principal: UsernamePasswordAuthenticationToken): JwtEncodingContext =
        JwtEncodingContext.with(jwsHeaderBuilder(), JwtClaimsSet.builder())
            .registeredClient(registeredClient)
            .principal(principal)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .build()

    @Test
    fun `access token에 roles authorities 주입 (RBAC B — ROLE_ prefix 제거, permission은 항상 빈 목록)`() {
        val principal = UsernamePasswordAuthenticationToken(
            "acc-uuid-1", null, listOf(SimpleGrantedAuthority("ROLE_EVENT_ADMIN")),
        )
        val context = accessTokenContext(principal)

        customizer.customize(context)

        val claims = context.claims.build().claims
        @Suppress("UNCHECKED_CAST")
        val roles = claims["roles"] as Collection<String>
        @Suppress("UNCHECKED_CAST")
        val authorities = claims["authorities"] as Collection<String>
        assertEquals(setOf("EVENT_ADMIN"), roles.toSet())
        assertTrue(authorities.isEmpty(), "RBAC B — permission 세분화 미도입, authorities는 항상 빈 목록")
    }

    @Test
    fun `EventScopePort가 null을 반환하면 event_ids claim 자체가 없다 (SYSTEM_ADMIN)`() {
        val principal = UsernamePasswordAuthenticationToken(
            "sysadmin-uuid", null, listOf(SimpleGrantedAuthority("ROLE_SYSTEM_ADMIN")),
        )
        val context = accessTokenContext(principal)

        customizer.customize(context)

        assertFalse(context.claims.build().claims.containsKey("event_ids"), "SYSTEM_ADMIN은 event_ids claim 자체가 부재해야 함")
    }

    @Test
    fun `EventScopePort가 빈 배열을 반환하면 event_ids claim은 존재한다 (배정 0건 — null과 구분)`() {
        val eventScopePort = mockk<EventScopePort>()
        every { eventScopePort.resolveEventIds("staff-uuid") } returns emptyList()
        val sut = TokenCustomizerConfig(eventScopePort, noopAccountUseCase).tokenCustomizer()

        val principal = UsernamePasswordAuthenticationToken(
            "staff-uuid", null, listOf(SimpleGrantedAuthority("ROLE_EVENT_STAFF")),
        )
        val context = accessTokenContext(principal)

        sut.customize(context)

        val claims = context.claims.build().claims
        assertTrue(claims.containsKey("event_ids"), "역할이 있으면 배정이 0건이라도 claim 자체는 존재해야 함")
        @Suppress("UNCHECKED_CAST")
        assertTrue((claims["event_ids"] as Collection<String>).isEmpty())
    }

    @Test
    fun `EventScopePort가 event_id 목록을 반환하면 배열 그대로 event_ids claim에 주입한다`() {
        val eventScopePort = mockk<EventScopePort>()
        every { eventScopePort.resolveEventIds("admin-uuid") } returns listOf("event-1", "event-2")
        val sut = TokenCustomizerConfig(eventScopePort, noopAccountUseCase).tokenCustomizer()

        val principal = UsernamePasswordAuthenticationToken(
            "admin-uuid", null, listOf(SimpleGrantedAuthority("ROLE_EVENT_ADMIN")),
        )
        val context = accessTokenContext(principal)

        sut.customize(context)

        @Suppress("UNCHECKED_CAST")
        val eventIds = context.claims.build().claims["event_ids"] as Collection<String>
        assertEquals(listOf("event-1", "event-2"), eventIds.toList())
    }

    @Test
    fun `ID_TOKEN + email scope 부여 시 email claim 주입 (AccountUseCase findById)`() {
        val accountId = "acc-email-1"
        val expectedEmail = "admin@morymaker.co.kr"
        val accountUseCase = mockk<AccountUseCase>()
        every { accountUseCase.findById(accountId) } returns accountOf(id = accountId, email = expectedEmail)
        val eventScopePort = mockk<EventScopePort>(relaxed = true)
        val sut = TokenCustomizerConfig(eventScopePort, accountUseCase).tokenCustomizer()

        val clientWithEmail = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("test-client-email")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("https://example.test/callback")
            .scope("openid").scope("email")
            .build()
        val principal = UsernamePasswordAuthenticationToken(
            accountId, null, listOf(SimpleGrantedAuthority("ROLE_EVENT_ADMIN")),
        )
        val context = JwtEncodingContext.with(jwsHeaderBuilder(), JwtClaimsSet.builder().subject(accountId))
            .registeredClient(clientWithEmail)
            .principal(principal)
            .tokenType(OAuth2TokenType("id_token"))
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizedScopes(setOf("openid", "email"))
            .build()

        sut.customize(context)

        val claims = context.claims.build().claims
        assertEquals(expectedEmail, claims["email"])
        assertFalse(claims.containsKey("roles"), "ID_TOKEN에는 roles 미주입(identity≠authz 분리)")
        assertFalse(claims.containsKey("event_ids"), "ID_TOKEN에는 event_ids 미주입(access token 전용)")
    }

    @Test
    fun `ID_TOKEN이라도 email scope 없으면 email claim 미주입`() {
        val accountId = "acc-email-2"
        val accountUseCase = mockk<AccountUseCase>(relaxed = true)
        val eventScopePort = mockk<EventScopePort>(relaxed = true)
        val sut = TokenCustomizerConfig(eventScopePort, accountUseCase).tokenCustomizer()

        val principal = UsernamePasswordAuthenticationToken(
            accountId, null, listOf(SimpleGrantedAuthority("ROLE_EVENT_ADMIN")),
        )
        // registeredClient(this 파일 상단) scope=openid only → authorizedScopes 기본값에 email 없음.
        val context = JwtEncodingContext.with(jwsHeaderBuilder(), JwtClaimsSet.builder().subject(accountId))
            .registeredClient(registeredClient)
            .principal(principal)
            .tokenType(OAuth2TokenType("id_token"))
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .build()

        sut.customize(context)

        assertFalse(context.claims.build().claims.containsKey("email"), "email scope 없으면 email claim 미주입(scope-gated)")
    }

    private fun accountOf(id: String, email: String) = Account(
        id = id,
        email = email,
        name = "테스트",
        role = "EVENT_ADMIN",
        status = Account.STATUS_ACTIVE,
        passwordHash = "{bcrypt-hash}",
        failedAttempts = 0,
        lockedAt = null,
        lockedUntil = null,
        note = null,
        createdAt = Instant.now(),
    )
}
