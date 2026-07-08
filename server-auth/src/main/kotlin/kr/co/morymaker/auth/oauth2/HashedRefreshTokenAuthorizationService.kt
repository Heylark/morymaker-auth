package kr.co.morymaker.auth.oauth2

import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import kr.co.morymaker.auth.application.port.out.refresh.ConsumedRefreshTokenPort
import kr.co.morymaker.auth.util.RefreshTokenHashUtil
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.transaction.support.TransactionTemplate
import java.time.Duration
import java.time.Instant

/**
 * refresh token at-rest SHA-256 해시 + **재사용 탐지·패밀리 무효화**를 주입하는
 * [OAuth2AuthorizationService] **Decorator**.
 *
 * ## WHY — Decorator(위임 래퍼)인 이유 (Subclass 아님)
 * SAS `JdbcOAuth2AuthorizationService`를 직접 상속하면 해시 주입에 필요한 내부 메서드
 * (`toSqlParameterList`·`mapToSqlParameter`)가 모두 `private static`이라 selective `super` 호출이 불가능하다.
 * write·read 모두 어차피 메서드 전체 override가 되므로 상속의 이점이 없다.
 * → 공개 인터페이스 4-메서드만 구현하는 Decorator가 결합도가 낮고(내부 시그니처 비의존) 테스트가 쉽다
 *   (delegate를 mock으로 교체 가능). SAS 업그레이드에도 안전.
 *
 * ## 해시 경계 요약 (어느 메서드가 해시를 건드리는가)
 * | 메서드 | 해시 처리 | 이유 |
 * |-------|---------|-----|
 * | `save` | refresh 토큰이 raw면 해시 후 저장 (멱등 가드) + **consumed-hash 기록** | DB 평문 노출 차단 (write 경계) + 재사용 탐지를 위한 기록 |
 * | `findByToken(REFRESH_TOKEN)` | 입력을 해시 후 조회 + **재사용 탐지** | 컬럼이 해시라 raw로는 못 찾음 + null 분기에서 consumed check |
 * | `findByToken(null)` | raw 우선 → 미발견 시 해시 재조회 (2단계). **consumed check 금지** | revoke·introspection silent-fail 차단 / self-trigger 방지 |
 * | `findByToken(기타 타입)` | raw 그대로 | access/code/id는 평문 저장 — 해시 대상 아님 |
 * | `remove` / `findById` | raw 위임 (해시 무관) | SAS는 id 기반 — 토큰 값 미관여 |
 *
 * ## 재사용 탐지 (grace 정책 — grace suppress-kill)
 * 소비된 토큰 재제시 시 [ConsumedRefreshTokenPort]로 이전 소비 기록을 조회한다.
 * - consumed 기록 없음 → 단순 만료/미발급 (SAS `InvalidGrantException` 그대로)
 * - consumed 기록 있음 + grace(30초) 내 → 패밀리 무효화 **억제** (invalid_grant, UX 보호)
 * - consumed 기록 있음 + grace 초과 → 패밀리 **무효화** (invalid_grant)
 *
 * ## ⚠️ read-method side-effect (KDoc 필수 이유)
 * `findByToken(REFRESH_TOKEN)`은 읽기 메서드이지만 null 분기에서 `delegate.remove()`(파괴적)를 유발할 수 있다.
 * 이는 SAS가 refresh grant를 이 메서드로 라우팅 + null 분기가 재제시 판별 지점이기 때문이다.
 *
 * ## ⚠️ @Transactional 어노테이션 금지
 * 이 클래스는 `AuthorizationServerConfig.authorizationService` `@Bean` 에서 `new`로 직접 생성된다.
 * Spring AOP 프록시가 **절대 감싸지 않으므로** `@Transactional` 어노테이션은 silent-ignore 된다.
 * `save()`의 record-before-overwrite 원자성은 [TransactionTemplate]으로 **프로그래매틱하게** 보장한다.
 *
 * @param delegate         실제 영속화를 담당하는 SAS Jdbc 서비스 (Config에서 inline 생성하여 주입)
 * @param consumedPort     소비된 refresh token 해시 레지스트리 port-out
 * @param txTemplate       record-before-overwrite 원자성 보장용 프로그래매틱 Tx (AOP 프록시 미적용이라 필수)
 * @param meterRegistry    비즈니스 메트릭 계측 — refresh family_revoked 카운터 (Bean 미등록 클래스라 생성자 직접 주입)
 */
class HashedRefreshTokenAuthorizationService(
    private val delegate: OAuth2AuthorizationService,
    private val consumedPort: ConsumedRefreshTokenPort,
    private val txTemplate: TransactionTemplate,
    private val meterRegistry: MeterRegistry,
) : OAuth2AuthorizationService {

    private val log = LoggerFactory.getLogger(javaClass)

    companion object {
        /** grace 창(suppress-kill 의미론): 30초 내 동일 hash 재제시는 패밀리 무효화 억제. */
        private val GRACE_WINDOW: Duration = Duration.ofSeconds(30)

        /**
         * consumed-hash TTL safety margin.
         * 구 토큰 실 만료에 margin을 더해 clock skew·기록 지연을 흡수한다.
         */
        private val TTL_SAFETY_MARGIN: Duration = Duration.ofMinutes(5)
    }

    // ────────────────────────────────────────────────────────────────────────
    // save() — rotation 기록
    // ────────────────────────────────────────────────────────────────────────

    /**
     * 인가 저장 — refresh 토큰을 **at-rest 해시**로 교체하고, rotation 시 구 토큰 해시를 기록한다.
     *
     * ## 흐름 (record-before-overwrite)
     * 1. refresh 토큰이 없으면(authorization_code 1차 저장 등) → 그대로 위임 (해시 대상 없음).
     * 2. raw 토큰이면 해시 산출 / 이미 해시면 멱등 가드(hash(hash) 방지).
     * 3. `delegate.findById(authorization.id)` — DB 기존 행에서 R_old 해시 추출.
     * 4. ★ record-before-overwrite (단일 Tx, `txTemplate` 내):
     *    - oldHash ≠ null && oldHash ≠ incomingHash → consumed INSERT (TTL 기반)
     *    - overwrite 이전 record 순서 강제 + 동일 Tx → crash window silent gap 차단
     * 5. `delegate.save(rebuilt)` — 해시 교체 후 overwrite.
     *
     * ## ⚠️ fail-CLOSED
     * record 실패 시 예외를 전파한다 → rotation 전체 실패 (새 refresh token 미발급).
     * catch-and-ignore는 crash window를 열어 fail-OPEN과 동등한 결과를 낳는다.
     *
     * ## ⚠️ @Transactional 금지
     * AOP 프록시 비사용 구조라 어노테이션은 silent-ignore. [txTemplate]으로 프로그래매틱 Tx 필수.
     */
    override fun save(authorization: OAuth2Authorization) {
        // 1. refresh 토큰이 없으면 그대로 위임 (code 발급 단계 등 — 기록 대상 없음).
        val refreshTokenHolder = authorization.refreshToken
        if (refreshTokenHolder == null) {
            delegate.save(authorization)
            return
        }

        val rawOrHashedValue = refreshTokenHolder.token.tokenValue

        // 2. 해시 산출 (멱등 가드: 이미 해시면 재해시 방지).
        val incomingHash: String = if (RefreshTokenHashUtil.isHashed(rawOrHashedValue)) {
            // 이미 해시 → 그대로 사용 (reuseRefreshTokens=true 재저장·revoke 경로).
            rawOrHashedValue
        } else {
            RefreshTokenHashUtil.hash(rawOrHashedValue)
        }

        // 해시 교체된 인가 객체 미리 구성 (Tx 내에서 쓸 rebuilt).
        val original = refreshTokenHolder.token
        val hashedRefreshToken = OAuth2RefreshToken(
            incomingHash,
            original.issuedAt,
            original.expiresAt,
        )

        // ★ OAuth2Authorization.from() 이 id·principalName·grantType·scopes·
        //   tokens map 전체(access token 포함)·attributes 를 복사한다 (SAS 소스 검증).
        //   token(hashedRefreshToken){...} 은 동일 class(OAuth2RefreshToken) 슬롯을 교체하고 metadata를 보존한다.
        val rebuilt = OAuth2Authorization.from(authorization)
            .token(hashedRefreshToken) { metadata -> metadata.putAll(refreshTokenHolder.metadata) }
            .build()

        // 3-5: record-before-overwrite 단일 Tx (ambient Tx 부재 — 아래 AOP 프록시 미적용 사유).
        // @Transactional 어노테이션 의존 금지 — Spring AOP proxy가 이 클래스를 감싸지 않음.
        txTemplate.executeWithoutResult { _ ->
            // 3. DB 기존 행에서 R_old 해시 추출 (rotation 시 R_new가 들어오므로 기존 행 조회 필수).
            //    첫 발급이면 existing == null (기록 스킵).
            val existing = delegate.findById(authorization.id)
            val oldHash = existing?.refreshToken?.token?.tokenValue

            // 4. ★ record-before-overwrite
            //    oldHash == null  → 첫 발급 (기록 대상 없음)
            //    oldHash == incomingHash → idempotent 재저장·revoke re-save (군더더기 entry 0)
            //    그 외(rotation 확정) → consumed INSERT (TTL: R_old 실 만료 + safetyMargin)
            if (oldHash != null && oldHash != incomingHash) {
                // 구 토큰 실 만료(expiresAt는 at-rest 해시 교체(rehash) 시 보존됨) + margin.
                //     null(비-만료 refresh) 시 현재 기준 60분 fallback.
                val oldExpiresAt: Instant = existing.refreshToken!!.token.expiresAt
                    ?: (Instant.now() + buildRefreshTtlFallback())
                val consumedExpiresAt = oldExpiresAt + TTL_SAFETY_MARGIN

                // fail-CLOSED: 예외 전파 → rotation 전체 실패 (새 refresh token 미발급). catch 금지.
                consumedPort.record(oldHash, authorization.id, consumedExpiresAt)
                log.debug("refresh token consumed-hash recorded: authorizationId={}", authorization.id)
            }

            // 5. overwrite — 4(record)가 성공한 경우에만 여기 도달 (단일 Tx 보장).
            delegate.save(rebuilt)
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // remove / findById — 위임 (id 기반 삭제·조회라 해시 무관)
    // ────────────────────────────────────────────────────────────────────────

    /**
     * 인가 삭제 — 그대로 위임한다 (해시 무관, id 기반 삭제).
     *
     * ## WHY — remove()에는 해시 가드가 필요 없다
     * SAS `remove()`는 **id 기반** `DELETE WHERE id = ?` 라 토큰 값이 전혀 개입하지 않는다.
     *
     * ⚠️ 단, **revoke는 remove()가 아니라 save() 경로**다(`OAuth2TokenRevocationAuthenticationProvider`는
     * `invalidate()` 후 `save()` 호출). 따라서 이중 해시 방어는 remove()가 아니라 save()의 멱등 가드가 담당한다.
     */
    override fun remove(authorization: OAuth2Authorization) {
        delegate.remove(authorization)
    }

    /**
     * id로 인가 조회 — 그대로 위임 (id 기반, 해시 무관).
     */
    override fun findById(id: String): OAuth2Authorization? = delegate.findById(id)

    // ────────────────────────────────────────────────────────────────────────
    // findByToken() — 재사용 탐지
    // ────────────────────────────────────────────────────────────────────────

    /**
     * 토큰 값으로 인가 조회 — refresh 컬럼은 해시 저장이므로 토큰 타입별로 분기하고,
     * **REFRESH_TOKEN null 분기에서 재사용 탐지·패밀리 무효화**를 수행한다.
     *
     * - [OAuth2TokenType.REFRESH_TOKEN] : 해시 후 조회 → null이면 **consumed check** (재사용 탐지).
     * - `null` (revoke·introspection 등 타입 미지정) : [findByTokenNullType] 의 2단계 분기.
     *   **consumed check 절대 금지** (self-trigger 방지).
     * - 그 외(ACCESS_TOKEN·STATE·CODE·ID_TOKEN 등) : raw 그대로 위임.
     *
     * ## ⚠️ read-method side-effect
     * `REFRESH_TOKEN` + null 분기에서 `delegate.remove()`(파괴적)를 유발할 수 있다.
     * SAS가 refresh grant를 이 메서드로 라우팅하고, null 분기가 재제시 판별 지점이기 때문이다.
     *
     * ## ⚠️ fail-CLOSED
     * consumed check·패밀리 무효화 구간 예외 발생 시 `null`을 반환하여
     * `InvalidGrantException`으로 처리한다 (silent-allow = hit 재반환 절대 금지).
     */
    override fun findByToken(token: String, tokenType: OAuth2TokenType?): OAuth2Authorization? {
        return when {
            tokenType == OAuth2TokenType.REFRESH_TOKEN ->
                findByRefreshToken(token)

            tokenType == null ->
                findByTokenNullType(token)

            else ->
                // access/code/id 등 typed lookup — 평문 저장이라 raw 그대로 조회.
                delegate.findByToken(token, tokenType)
        }
    }

    /**
     * REFRESH_TOKEN 타입 조회 + 재사용 탐지.
     *
     * 흐름:
     * 1. 해시 후 delegate 조회 (hit ≠ null → 활성 토큰, 그대로 반환 — consumed 조회 안 함).
     * 2. hit == null → 활성 행 없음. consumed check (재사용 의심 분기):
     *    2a. consumed 기록 없음 → 단순 만료/미발급 → null (SAS `InvalidGrantException` 그대로).
     *    2b. consumed 기록 있음 (재사용 확정):
     *        - grace 내(consumedAt + 30초 > NOW()) → 패밀리 무효화 억제 (suppress-kill)
     *        - grace 초과 → `delegate.findById(lookup.authorizationId)?.let { delegate.remove(it) }`
     *        → 항상 null 반환 (invalid_grant, replay 없음).
     * 3. fail-CLOSED: 2~2b 구간 예외 → catch → null (silent-allow 절대 금지).
     */
    private fun findByRefreshToken(token: String): OAuth2Authorization? {
        // 1. 활성 토큰 경로 (정상 refresh grant).
        val tokenHash = RefreshTokenHashUtil.hash(token)
        val hit = delegate.findByToken(tokenHash, OAuth2TokenType.REFRESH_TOKEN)
        if (hit != null) {
            // 활성 행 존재 → consumed 조회 생략 (false-positive kill 방지). 그대로 반환.
            return hit
        }

        // 2. 활성 행 없음 → 재사용 의심. fail-CLOSED: 예외 발생 시 catch → null.
        return try {
            val lookup = consumedPort.findConsumed(tokenHash)

            when {
                lookup == null -> {
                    // 2a. consumed 기록 없음 → 단순 만료/미발급. SAS가 InvalidGrantException을 내도록 null 반환.
                    null
                }
                isWithinGrace(lookup.consumedAt) -> {
                    // 2b-suppress: grace 내 재제시 → 패밀리 무효화 억제 (suppress-kill 의미론).
                    // 정상 멀티탭·BFF 재시도의 stray R_old 방어. 다른 세션·현재 R_new 보존.
                    // ⚠️ authorizationId만 로그 허용 — hash 출력 금지.
                    log.info("refresh reuse detected (grace suppressed): authorizationId={}", lookup.authorizationId)
                    // grace-suppressed 카운터. runCatching: 계측 실패가 invalid_grant 반환을 막으면 안 된다.
                    runCatching {
                        Counter.builder("morymaker.refresh.family_revoked")
                            .tag("outcome", "grace_suppressed")
                            .register(meterRegistry).increment()
                    }
                    null // invalid_grant — 응답 replay 없음 (이 레이어는 응답 보관 불가)
                }
                else -> {
                    // 2b-kill: grace 초과 → 탈취 재생으로 판정. 패밀리 전체 무효화.
                    val family = delegate.findById(lookup.authorizationId)
                    if (family != null) {
                        delegate.remove(family)
                        log.warn("refresh token family revoked (reuse detected): authorizationId={}", lookup.authorizationId)
                        // ★ 카운터는 delegate.remove() 완료 이후 — "무효화 완료" 의미(계측 지점을 명확히 하기 위함).
                        // runCatching: 계측 실패가 family-kill 보안 동작을 방해해선 안 된다.
                        runCatching {
                            Counter.builder("morymaker.refresh.family_revoked")
                                .tag("outcome", "killed")
                                .register(meterRegistry).increment()
                        }
                    } else {
                        // 패밀리가 이미 삭제된 경우(이전 무효화·만료 정리) — consumed 기록만 남은 상태. 정상.
                        log.info("refresh reuse detected but family already absent: authorizationId={}", lookup.authorizationId)
                    }
                    null // invalid_grant
                }
            }
        } catch (ex: Exception) {
            // fail-CLOSED: consumed check 구간 예외 → null 반환 (invalid_grant).
            // silent-allow(hit 재반환)는 탈취 토큰을 허용하는 보안 결함 — 절대 금지.
            log.error("consumed check failed (fail-CLOSED → invalid_grant): authorizationId lookup error", ex)
            null
        }
    }

    /**
     * null-tokenType 조회의 2단계 분기 (revoke silent-fail 차단).
     *
     * ## ⚠️ consumed check 절대 금지 (self-trigger 방지)
     * revoke 경로가 이 메서드를 통과한다. 여기서 consumed check를 하면:
     * revoke 요청 → `findByTokenNullType` → hash(token) → `findConsumed` → consumed 발견
     * → 패밀리 무효화 → 그 결과로 revoke가 이미 무효화된 토큰을 다시 처리 → 루프/오류.
     * 이 경로의 consumed check는 구조적으로 self-trigger를 만들므로 절대 금지.
     *
     * ## WHY — 왜 2단계인가
     * SAS `findByToken(token, null)`은 7개 컬럼(state·code·access·refresh·id·user_code·device_code)을 OR로 검색한다.
     * 이 중 refresh만 해시 저장이라, `/oauth2/revoke`가 raw refresh 토큰을 null 타입으로 넘기면
     * 해시 컬럼과 불일치해 **못 찾고 조용히 실패**(200 응답이지만 무효화 안 됨)한다.
     *
     * - ❌ 단순히 `findByToken(hash(token), null)`로 7컬럼을 전부 해시 검색하면
     *      access/code/id(평문 저장)가 깨진다.
     * - ✅ 채택: ① raw로 먼저 조회(refresh 외 6타입 정상 매칭) → ② 못 찾으면 그때만 해시로 refresh 컬럼 재조회.
     *
     * 비용: refresh revoke일 때만 2쿼리(저빈도). 일반 토큰은 ①에서 즉시 매칭돼 ②를 타지 않는다.
     */
    private fun findByTokenNullType(token: String): OAuth2Authorization? {
        // ① raw-pass: state/code/access/id/user_code/device_code 6타입을 raw로 매칭.
        //    refresh 컬럼은 raw≠해시라 무해하게 불일치(여기서 못 찾음).
        val rawHit = delegate.findByToken(token, null)
        if (rawHit != null) return rawHit

        // ② raw 미발견 → refresh 컬럼만 해시로 정확히 재조회 (revoke 대상 refresh 토큰).
        //    ⚠️ consumed check 절대 금지 — self-trigger 방지.
        return delegate.findByToken(RefreshTokenHashUtil.hash(token), OAuth2TokenType.REFRESH_TOKEN)
    }

    // ────────────────────────────────────────────────────────────────────────
    // 내부 헬퍼
    // ────────────────────────────────────────────────────────────────────────

    /**
     * grace 창 판정: consumedAt 이후 [GRACE_WINDOW] 이내면 true (suppress-kill).
     *
     * @param consumedAt consumed_refresh_tokens.consumed_at (DB 서버 시각)
     */
    private fun isWithinGrace(consumedAt: java.time.Instant): Boolean {
        return Instant.now() < consumedAt + GRACE_WINDOW
    }

    /**
     * consumed-hash TTL fallback — 구 토큰 expiresAt가 null(비-만료 refresh 설정)인 경우에만 쓰는 보수적 하한.
     *
     * web 클라이언트는 refresh TTL을 항상 지정(비-만료 설정 없음)하므로 실 운영에서 이 경로에 도달하지
     * 않지만, 방어적으로 짧은 고정 하한을 둔다. 클라이언트 설정 TTL을 여기서 다시 읽지 않는 이유는
     * 클라이언트 관리 서비스 직접 의존을 피하기 위함(의존 방향 smell) — consumed 기록의 잔류 상한일 뿐이라
     * 실제 refresh 만료(토큰 자체의 expiresAt)와 무관하다.
     */
    private fun buildRefreshTtlFallback(): Duration = Duration.ofMinutes(60)
}
