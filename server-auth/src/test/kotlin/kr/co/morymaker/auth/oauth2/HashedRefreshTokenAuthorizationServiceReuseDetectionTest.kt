package kr.co.morymaker.auth.oauth2

import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.verify
import kr.co.morymaker.auth.application.port.out.refresh.ConsumedRefreshTokenPort
import kr.co.morymaker.auth.domain.refresh.ConsumedRefreshToken
import kr.co.morymaker.auth.util.RefreshTokenHashUtil
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.TransactionStatus
import org.springframework.transaction.support.TransactionTemplate
import java.time.Instant

/**
 * [HashedRefreshTokenAuthorizationService] 재사용 탐지·패밀리 무효화 단위 테스트 (기본 smoke).
 *
 * ## 테스트 범위
 * - findByToken(REFRESH_TOKEN) null 분기: consumed 재제시 → remove 호출 검증 (mutation-prove)
 * - 활성 토큰 → consumed check 스킵 (false-positive kill 방지)
 * - grace 내 재제시 → remove 억제 (suppress-kill)
 * - save() rotation → consumed INSERT + overwrite 순서 (record-before-overwrite)
 * - save() 첫 발급 → INSERT 스킵 (existing == null)
 * - save() record 실패 → 예외 전파 (fail-CLOSED)
 *
 * ## 설계 주의사항
 * [TransactionTemplate]은 [PlatformTransactionManager] mock에서 람다를 즉시 실행하도록 설정한다
 * (Tx 커밋·롤백 동작은 Spring 인프라가 보장 — 단위 테스트 범위 밖).
 */
class HashedRefreshTokenAuthorizationServiceReuseDetectionTest {

    private val delegate: OAuth2AuthorizationService = mockk()
    private val consumedPort: ConsumedRefreshTokenPort = mockk()

    // TransactionTemplate을 즉시 실행 mock으로 구성 — Tx 경계는 Spring이 보장, 여기선 로직 검증.
    private val txManager: PlatformTransactionManager = mockk()
    private val txTemplate = TransactionTemplate(txManager)
    private val registry = SimpleMeterRegistry()

    private lateinit var sut: HashedRefreshTokenAuthorizationService

    /** 테스트용 raw refresh 토큰 값 (SAS 포맷 모방 — base64url 충분한 길이) */
    private val rawToken = "test-raw-refresh-token-abc123XYZ_long-enough"
    private val tokenHash = RefreshTokenHashUtil.hash(rawToken)

    /** 고정 authorization id (UUID 형식) */
    private val authorizationId = "auth-id-00000000-0001"

    @BeforeEach
    fun setUp() {
        // TransactionTemplate.executeWithoutResult{} 가 람다를 즉시 실행하도록 mock.
        every { txManager.getTransaction(any()) } returns mockk<TransactionStatus>(relaxed = true)
        every { txManager.commit(any()) } returns Unit
        every { txManager.rollback(any()) } returns Unit

        sut = HashedRefreshTokenAuthorizationService(delegate, consumedPort, txTemplate, registry)
    }

    // ────────────────────────────────────────────────────────────────────────
    // findByToken(REFRESH_TOKEN) — 재사용 탐지
    // ────────────────────────────────────────────────────────────────────────

    @Nested
    inner class FindByRefreshToken {

        /**
         * 활성 토큰(hit ≠ null) → consumed 조회 스킵 → 활성 인가 그대로 반환.
         * false-positive kill 방지 — 정상 rotation 체인은 consumed check를 타면 안 됨.
         */
        @Test
        fun `활성 토큰은 consumed check 없이 즉시 반환된다`() {
            val activeAuth = buildAuthorization(id = authorizationId)
            every {
                delegate.findByToken(tokenHash, OAuth2TokenType.REFRESH_TOKEN)
            } returns activeAuth

            val result = sut.findByToken(rawToken, OAuth2TokenType.REFRESH_TOKEN)

            assert(result == activeAuth) { "활성 토큰은 그대로 반환되어야 함" }
            verify(exactly = 0) { consumedPort.findConsumed(any()) }
        }

        /**
         * consumed 재제시(grace 초과) → `delegate.remove()` 호출 → null 반환 (invalid_grant).
         * mutation-prove: 이 탐지 로직을 제거하면 테스트가 RED.
         */
        @Test
        fun `consumed 토큰 재제시(grace 초과)에서 패밀리가 무효화된다`() {
            val consumedRecord = ConsumedRefreshToken(
                tokenHash = tokenHash,
                authorizationId = authorizationId,
                consumedAt = Instant.now().minusSeconds(120), // grace(30초) 초과
                expiresAt = Instant.now().plusSeconds(3600),
            )
            val familyAuth = buildAuthorization(id = authorizationId)

            every { delegate.findByToken(tokenHash, OAuth2TokenType.REFRESH_TOKEN) } returns null
            every { consumedPort.findConsumed(tokenHash) } returns consumedRecord
            every { delegate.findById(authorizationId) } returns familyAuth
            justRun { delegate.remove(familyAuth) }

            val result = sut.findByToken(rawToken, OAuth2TokenType.REFRESH_TOKEN)

            assertNull(result, "재사용 탐지 후 null(invalid_grant) 반환 필수")
            verify(exactly = 1) { delegate.remove(familyAuth) }
        }

        /**
         * consumed 재제시(grace 내, 30초 이내) → 무효화 억제 → null 반환 (suppress-kill).
         * 멀티탭·BFF 재시도 false-positive로부터 다른 세션 보호.
         */
        @Test
        fun `grace 내 재제시에서 패밀리 무효화가 억제된다`() {
            val consumedRecord = ConsumedRefreshToken(
                tokenHash = tokenHash,
                authorizationId = authorizationId,
                consumedAt = Instant.now().minusSeconds(5), // grace(30초) 이내
                expiresAt = Instant.now().plusSeconds(3600),
            )

            every { delegate.findByToken(tokenHash, OAuth2TokenType.REFRESH_TOKEN) } returns null
            every { consumedPort.findConsumed(tokenHash) } returns consumedRecord

            val result = sut.findByToken(rawToken, OAuth2TokenType.REFRESH_TOKEN)

            assertNull(result, "grace 내 재제시도 invalid_grant(null) 반환 — 응답 replay 없음")
            verify(exactly = 0) { delegate.remove(any()) }
            verify(exactly = 0) { delegate.findById(any()) }
        }

        /**
         * consumed 기록 없음(단순 만료·미발급) → null 반환 (SAS InvalidGrantException 그대로).
         * 조용한 동작 — consumed check는 했지만 무효화할 대상이 없음.
         */
        @Test
        fun `consumed 기록 없으면 null을 반환한다(단순 만료)`() {
            every { delegate.findByToken(tokenHash, OAuth2TokenType.REFRESH_TOKEN) } returns null
            every { consumedPort.findConsumed(tokenHash) } returns null

            val result = sut.findByToken(rawToken, OAuth2TokenType.REFRESH_TOKEN)

            assertNull(result)
            verify(exactly = 0) { delegate.remove(any()) }
        }

        /**
         * consumed check 구간 예외 → fail-CLOSED → null 반환 (silent-allow = hit 재반환 절대 금지).
         * DB 장애 시에도 탈취 토큰이 허용되어선 안 됨.
         */
        @Test
        fun `consumed check 예외 발생 시 fail-CLOSED로 null을 반환한다`() {
            every { delegate.findByToken(tokenHash, OAuth2TokenType.REFRESH_TOKEN) } returns null
            every { consumedPort.findConsumed(tokenHash) } throws RuntimeException("DB connection lost")

            val result = sut.findByToken(rawToken, OAuth2TokenType.REFRESH_TOKEN)

            assertNull(result, "fail-CLOSED: consumed check 예외 → null(invalid_grant), silent-allow 금지")
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // save() — rotation 기록 (record-before-overwrite)
    // ────────────────────────────────────────────────────────────────────────

    @Nested
    inner class Save {

        /**
         * rotation save() → consumed INSERT + delegate.save() 순서 검증.
         * record-before-overwrite 불변식: INSERT가 먼저, overwrite가 그 다음.
         *
         * ## mutation-prove
         * consumedPort.record 호출을 제거하면 이 테스트가 RED.
         */
        @Test
        fun `rotation 시 consumed INSERT 후 overwrite가 실행된다`() {
            val now = Instant.now()
            val expiresAt = now.plusSeconds(3600)

            // 기존 DB 행 (R_old 포함)
            val existingAuth = buildAuthorizationWithRefreshToken(
                id = authorizationId,
                tokenValue = tokenHash, // DB에는 해시값이 저장됨
                expiresAt = expiresAt,
            )
            // incoming authorization (rotation 후 R_new)
            val newRawToken = "new-raw-refresh-token-after-rotation"
            val newIncomingAuth = buildAuthorizationWithRefreshToken(
                id = authorizationId,
                tokenValue = newRawToken, // raw
                expiresAt = expiresAt,
            )

            every { delegate.findById(authorizationId) } returns existingAuth
            justRun { consumedPort.record(tokenHash, authorizationId, any()) }
            justRun { delegate.save(any()) }

            sut.save(newIncomingAuth)

            // record가 호출됐는지 (mutation-prove: 이 호출이 없으면 RED)
            verify(exactly = 1) { consumedPort.record(tokenHash, authorizationId, any()) }
            // overwrite(delegate.save)도 호출됨
            verify(exactly = 1) { delegate.save(any()) }
        }

        /**
         * 첫 발급 save() (existing == null) → consumed INSERT 스킵.
         * 새 refresh 토큰 발급 시에는 overwrite할 R_old가 없으므로 기록 불필요.
         */
        @Test
        fun `첫 발급 시 consumed INSERT가 호출되지 않는다`() {
            val rawToken = "brand-new-raw-refresh-token"
            val auth = buildAuthorizationWithRefreshToken(
                id = authorizationId,
                tokenValue = rawToken,
                expiresAt = Instant.now().plusSeconds(3600),
            )

            every { delegate.findById(authorizationId) } returns null // 첫 발급 — 기존 행 없음
            justRun { delegate.save(any()) }

            sut.save(auth)

            verify(exactly = 0) { consumedPort.record(any(), any(), any()) }
            verify(exactly = 1) { delegate.save(any()) }
        }

        /**
         * record 실패 → 예외 전파 → rotation 전체 실패 (새 refresh token 미발급) — fail-CLOSED.
         * catch-and-ignore는 crash window를 여는 fail-OPEN과 동등 — 금지.
         */
        @Test
        fun `record 실패 시 예외가 전파된다(fail-CLOSED)`() {
            val existingHash = tokenHash
            val existingAuth = buildAuthorizationWithRefreshToken(
                id = authorizationId,
                tokenValue = existingHash,
                expiresAt = Instant.now().plusSeconds(3600),
            )
            val newAuth = buildAuthorizationWithRefreshToken(
                id = authorizationId,
                tokenValue = "new-raw-token-after-rotation",
                expiresAt = Instant.now().plusSeconds(3600),
            )

            every { delegate.findById(authorizationId) } returns existingAuth
            every { consumedPort.record(any(), any(), any()) } throws RuntimeException("DB write failed")

            assertThrows<RuntimeException> { sut.save(newAuth) }
            // overwrite(delegate.save)가 호출되지 않음 — 새 refresh token 미발급 보장
            verify(exactly = 0) { delegate.save(any()) }
        }

        /**
         * refresh 토큰 없는 save() (authorization_code 1차 저장) → 즉시 위임.
         * 해시 대상도, consumed 기록 대상도 없음.
         */
        @Test
        fun `refresh 토큰 없는 save는 즉시 위임된다`() {
            val authWithoutRefresh = buildAuthorization(id = authorizationId)
            justRun { delegate.save(authWithoutRefresh) }

            sut.save(authWithoutRefresh)

            verify(exactly = 1) { delegate.save(authWithoutRefresh) }
            verify(exactly = 0) { consumedPort.record(any(), any(), any()) }
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // 메트릭 mutation-prove 테스트 — 카운터 제거 시 TC가 실패해야 함(정적 존재만 확인하는 동어반복 테스트 금지)
    // ────────────────────────────────────────────────────────────────────────

    @Nested
    inner class MetricsMutationProve {

        /**
         * grace 초과 재제시 → family kill → morymaker.refresh.family_revoked{outcome=killed} +1.
         *
         * ★ mutation-prove: 카운터 라인을 제거하면 count == 0 → RED.
         * fail-safe 보장: counter가 없어도 null(invalid_grant)은 반환되어야 한다 (family-kill 동작 보존).
         */
        @Test
        fun `grace 초과 재제시 시 family_revoked(killed) 카운터가 증가한다`() {
            val consumedRecord = ConsumedRefreshToken(
                tokenHash = tokenHash,
                authorizationId = authorizationId,
                consumedAt = Instant.now().minusSeconds(120),
                expiresAt = Instant.now().plusSeconds(3600),
            )
            val familyAuth = buildAuthorization(id = authorizationId)

            every { delegate.findByToken(tokenHash, OAuth2TokenType.REFRESH_TOKEN) } returns null
            every { consumedPort.findConsumed(tokenHash) } returns consumedRecord
            every { delegate.findById(authorizationId) } returns familyAuth
            justRun { delegate.remove(familyAuth) }

            val before = registry.counter("morymaker.refresh.family_revoked", "outcome", "killed").count()
            sut.findByToken(rawToken, OAuth2TokenType.REFRESH_TOKEN)
            val after = registry.counter("morymaker.refresh.family_revoked", "outcome", "killed").count()

            assert(after == before + 1.0) { "killed 카운터가 1 증가해야 함 (before=$before, after=$after)" }
        }

        /**
         * grace 내 재제시 → suppress → morymaker.refresh.family_revoked{outcome=grace_suppressed} +1.
         *
         * ★ mutation-prove: 카운터 라인을 제거하면 count == 0 → RED.
         */
        @Test
        fun `grace 내 재제시 시 family_revoked(grace_suppressed) 카운터가 증가한다`() {
            val consumedRecord = ConsumedRefreshToken(
                tokenHash = tokenHash,
                authorizationId = authorizationId,
                consumedAt = Instant.now().minusSeconds(5),
                expiresAt = Instant.now().plusSeconds(3600),
            )

            every { delegate.findByToken(tokenHash, OAuth2TokenType.REFRESH_TOKEN) } returns null
            every { consumedPort.findConsumed(tokenHash) } returns consumedRecord

            val before = registry.counter("morymaker.refresh.family_revoked", "outcome", "grace_suppressed").count()
            sut.findByToken(rawToken, OAuth2TokenType.REFRESH_TOKEN)
            val after = registry.counter("morymaker.refresh.family_revoked", "outcome", "grace_suppressed").count()

            assert(after == before + 1.0) { "grace_suppressed 카운터가 1 증가해야 함 (before=$before, after=$after)" }
        }

        /**
         * family kill 후 counter fail (MeterRegistry throw) → 동작 보존 검증 (fail-safe 불변식).
         * 계측 실패가 null(invalid_grant) 반환을 막아서는 안 된다.
         *
         * ThrowingMeterRegistry: SimpleMeterRegistry 를 상속해 실제 Counter.increment() 시점에 throw.
         * (MeterRegistry.registerMeter는 최종 저장 포인트이므로 override하면 register 단계에서 throw됨)
         */
        @Test
        fun `카운터 실패 시에도 null(invalid_grant)은 정상 반환된다(fail-safe)`() {
            val consumedRecord = ConsumedRefreshToken(
                tokenHash = tokenHash,
                authorizationId = authorizationId,
                consumedAt = Instant.now().minusSeconds(120),
                expiresAt = Instant.now().plusSeconds(3600),
            )
            val familyAuth = buildAuthorization(id = authorizationId)

            // SimpleMeterRegistry 상속 — newCounter 를 가로채 throw (Counter.register 시점에 발생)
            val throwingRegistry = object : io.micrometer.core.instrument.simple.SimpleMeterRegistry() {
                override fun newCounter(id: io.micrometer.core.instrument.Meter.Id): io.micrometer.core.instrument.Counter {
                    throw RuntimeException("registry down — 계측 fail-safe 검증용")
                }
            }
            val sutWithBadRegistry = HashedRefreshTokenAuthorizationService(delegate, consumedPort, txTemplate, throwingRegistry)

            every { delegate.findByToken(tokenHash, OAuth2TokenType.REFRESH_TOKEN) } returns null
            every { consumedPort.findConsumed(tokenHash) } returns consumedRecord
            every { delegate.findById(authorizationId) } returns familyAuth
            justRun { delegate.remove(familyAuth) }

            // runCatching 덕에 exception 전파 없이 null 반환
            val result = sutWithBadRegistry.findByToken(rawToken, OAuth2TokenType.REFRESH_TOKEN)
            assertNull(result, "counter 실패해도 null(invalid_grant) 반환 보장")
            // family-kill은 counter 실패와 무관하게 실행되어야 한다
            verify(exactly = 1) { delegate.remove(familyAuth) }
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // 헬퍼
    // ────────────────────────────────────────────────────────────────────────

    /**
     * 테스트용 [RegisteredClient] 픽스처.
     * [OAuth2Authorization.withRegisteredClient] 빌더가 clientId·grantType 최소 필드를 요구한다.
     */
    private val testRegisteredClient: RegisteredClient = RegisteredClient.withId("test-client-id")
        .clientId("test-client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("http://localhost/callback")
        .build()

    /** refresh 토큰이 없는 최소 [OAuth2Authorization] mock (단순 읽기 경로용). */
    private fun buildAuthorization(id: String): OAuth2Authorization {
        return mockk<OAuth2Authorization>(relaxed = true) {
            every { this@mockk.id } returns id
            every { refreshToken } returns null
        }
    }

    /**
     * 지정 tokenValue·expiresAt을 가진 refresh 토큰이 있는 실제 [OAuth2Authorization] 인스턴스.
     *
     * ## WHY — mock이 아닌 실제 빌더 사용
     * [HashedRefreshTokenAuthorizationService.save] 는 [OAuth2Authorization.from]을 호출하는데,
     * `from()` 내부에서 `authorization.tokens` **private field**에 직접 접근한다.
     * mockk는 private field 접근을 가로챌 수 없으므로 NPE가 발생한다.
     * → 실제 SAS 빌더로 인스턴스를 생성하면 private field가 올바르게 초기화된다.
     */
    private fun buildAuthorizationWithRefreshToken(
        id: String,
        tokenValue: String,
        expiresAt: Instant,
    ): OAuth2Authorization {
        val refreshToken = OAuth2RefreshToken(tokenValue, Instant.now(), expiresAt)
        return OAuth2Authorization.withRegisteredClient(testRegisteredClient)
            .id(id)
            .principalName("test-user")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .refreshToken(refreshToken)
            .build()
    }
}
