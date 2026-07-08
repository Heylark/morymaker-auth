package kr.co.morymaker.auth.application.port.out.refresh

import kr.co.morymaker.auth.domain.refresh.ConsumedRefreshToken
import java.time.Instant

/**
 * 소비된 refresh token 해시 레지스트리 port-out 인터페이스.
 *
 * 헥사고날 레이어: Application — 영속화 계층에 대한 추상화.
 * 구현: `kr.co.morymaker.auth.persistence.adapter.persistence.refresh.ConsumedRefreshTokenPersistenceAdapter`
 *       (internal @Component — module-persistence)
 *
 * ## 핵심 보안 계약
 * - [findConsumed]: 조회 결과에 `authorizationId`가 포함되어야 패밀리 무효화가 가능하다.
 * - [record]: fail-CLOSED 불변식 — 저장 실패 시 예외 전파. silent-ignore 금지.
 *   `record()` 실패 → 전체 rotation 실패(새 refresh token 미발급). 보안 단계의 의도된 trade-off.
 * - record 호출자(HashedRefreshTokenAuthorizationService.save())는 이 메서드 호출 후
 *   overwrite(delegate.save)를 수행한다 — **record-before-overwrite** 순서 강제.
 * - `tokenHash` 값을 로그에 출력하지 않는다 (재사용 탐지 레지스트리의 보안 불변식).
 */
interface ConsumedRefreshTokenPort {

    /**
     * 소비된 토큰 해시를 조회한다 (재사용 탐지).
     *
     * `expires_at > NOW()` 필터를 적용하여 만료 항목을 자연 제외한다(lazy-evict).
     *
     * @param tokenHash SHA-256 lowercase hex 64자
     * @return 소비 기록, 없으면 null (null = 단순 만료·미발급 → SAS InvalidGrantException 그대로)
     */
    fun findConsumed(tokenHash: String): ConsumedRefreshToken?

    /**
     * rotation 시 소비된 구 토큰 해시를 기록한다 (record-before-overwrite).
     *
     * ## fail-CLOSED 요구사항
     * 저장 실패 시 예외를 전파해야 한다. silent-ignore 금지 — 기록 누락은
     * crash window silent detection gap(fail-OPEN)과 동등한 결과를 낳는다.
     *
     * ## 호출 순서 강제 (단일 Tx 내)
     * `record()` → `delegate.save(rebuilt)` 순서로만 호출한다.
     * overwrite 후 record 호출은 순서 반전으로 fail-CLOSED 불변식을 깬다.
     *
     * @param tokenHash       SHA-256 lowercase hex 64자 (구 토큰 해시 = R_old)
     * @param authorizationId oauth2_authorization.id — 패밀리 무효화 식별자
     * @param expiresAt       이 기록의 만료일시 (구 토큰 실 만료 + safetyMargin)
     * @throws Exception      저장 실패 시 예외 전파 (호출자가 catch하면 rotation 전체 실패)
     */
    fun record(tokenHash: String, authorizationId: String, expiresAt: Instant)
}
