package kr.co.morymaker.auth.domain.refresh

import java.time.Instant

/**
 * rotation으로 소비된 refresh token 해시 레코드 (값 객체 — DB 테이블에 영속 저장해 재기동 후에도
 * 재사용 탐지 레지스트리가 유지되도록 하는 설계).
 *
 * ## 설계 결정: `data class` (불변 값 객체)
 * DB row를 직접 표현하는 불변 스냅샷이다. 모든 필드가 `val`이며 상태 변경이 없다.
 *
 * ## authorization_id 필드가 필수인 이유
 * consumed-hash 레지스트리가 `token_hash`만 보존하면 패밀리 무효화가 불가능하다.
 * rotation overwrite 후 원본 토큰 해시로는 더 이상 인가를 찾을 수 없으므로,
 * hash(R_old) → authorization_id 역참조가 이 VO 안에 **반드시** 존재해야
 * `delegate.findById(authorizationId)?.let { delegate.remove(it) }` 로 패밀리를 무효화할 수 있다.
 *
 * ## raw 토큰 필드 없음
 * raw 토큰은 서비스 레이어에서 해시된 후 이 VO를 통해 DB에 기록된다.
 * `tokenHash`(SHA-256 hex 64자)만 저장한다.
 *
 * ## 로그 주의
 * `tokenHash`는 로그에 출력하지 않는다. 무효화 이벤트 로그는 `authorizationId`만 허용.
 *
 * @param tokenHash       SHA-256 lowercase hex 64자. rotation으로 소비된 구 refresh token의 해시.
 * @param authorizationId oauth2_authorization.id — 패밀리 무효화 대상 식별자.
 * @param consumedAt      소비일시. grace 창 판정: NOW() - consumedAt <= graceWindow.
 * @param expiresAt       이 기록의 만료일시. 구 토큰의 실 만료 + safetyMargin.
 */
data class ConsumedRefreshToken(
    /** SHA-256 lowercase hex 64자. raw 토큰은 절대 이 필드에 저장하지 않는다. */
    val tokenHash: String,
    /**
     * 패밀리 무효화 대상 authorization의 ID.
     * oauth2_authorization.id 와 동일한 값이지만 FK 제약 없음
     * (패밀리 무효화 시 authorization 행이 먼저 삭제될 수 있어 FK 미선언).
     */
    val authorizationId: String,
    /** rotation 시 기록된 소비일시. grace 창 판정의 기준값. */
    val consumedAt: Instant,
    /**
     * 이 기록의 만료일시. `expires_at > NOW()` 필터로 lazy-evict.
     * 구 토큰 실 만료(oauth2_authorization row의 refresh_token_value 만료시각) + safetyMargin.
     */
    val expiresAt: Instant,
)
