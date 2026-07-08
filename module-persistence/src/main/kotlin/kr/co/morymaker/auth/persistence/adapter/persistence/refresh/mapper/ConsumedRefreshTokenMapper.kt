package kr.co.morymaker.auth.persistence.adapter.persistence.refresh.mapper

import kr.co.morymaker.auth.domain.refresh.ConsumedRefreshToken
import org.apache.ibatis.annotations.Mapper
import org.apache.ibatis.annotations.Param
import java.time.Instant

/**
 * consumed_refresh_tokens 테이블 MyBatis 매퍼 인터페이스 (refresh 토큰 재사용 탐지 — consumed-hash DB 레지스트리).
 *
 * 헥사고날 레이어: persistence (mapper) — DB 관심사만 담당한다.
 * 메서드명은 DB 언어(fetch/insert)를 따른다. 도메인 언어(find/record) 누출 금지.
 *
 * XML 정의: resources/mapper/refresh/ConsumedRefreshTokenMapper.xml
 *
 * ## 평면 테이블 → 직접 매핑
 * consumed_refresh_tokens는 nested collection이 없는 평면 테이블이다.
 * BaseResultMap이 [ConsumedRefreshToken] 불변 data class로 직접 매핑.
 * `<constructor>` 선언 순서는 [ConsumedRefreshToken] 주 생성자 파라미터 순서와 정확히 일치해야 한다.
 *
 * ## PK 설계 (UUID)
 * DB PK는 `id` (CHAR(36) UUID). [ConsumedRefreshToken] VO는 `id` 필드를 가지지 않는다(도메인에서 불필요).
 * [insert] 호출자가 `java.util.UUID.randomUUID()`로 생성하여 전달한다.
 *
 * ## timezone 안전 (lazy-evict 필터)
 * [fetchByHash]의 만료 필터는 `expires_at > #{now}` JDBC 파라미터 바인딩을 사용한다.
 * DB 서버 `NOW()` 비사용 — MariaDB DATETIME(timezone 미포함) + JDBC serverTimezone 미설정
 * 환경에서 오프셋이 발생해 live 해시가 만료 오판될 수 있다(fail-OPEN 위험).
 * 호출자가 `java.time.Clock.systemUTC()`에서 `Instant.now(clock)`을 공급한다.
 *
 * ## 보안 주의
 * - 모든 WHERE 조건은 XML에서 #{} PreparedStatement 바인딩 필수 (${} 직접 치환 금지).
 * - tokenHash 값을 로그에 출력하지 않는다.
 */
@Mapper
interface ConsumedRefreshTokenMapper {

    // ── 조회 ──────────────────────────────────────────────────────────────

    /**
     * token_hash로 소비 기록을 조회한다 (만료 항목 자연 제외 — lazy-evict).
     *
     * `WHERE token_hash = #{tokenHash} AND expires_at > #{now}` 필터 적용.
     *
     * @param tokenHash SHA-256 lowercase hex 64자
     * @param now       만료 필터 기준 시각 (호출자가 Instant.now(clock) 공급 — UTC 기준, timezone 안전)
     * @return 소비 기록, 없으면 null
     */
    fun fetchByHash(
        @Param("tokenHash") tokenHash: String,
        @Param("now") now: Instant,
    ): ConsumedRefreshToken?

    // ── 저장 ──────────────────────────────────────────────────────────────

    /**
     * 소비된 토큰 해시를 INSERT한다 (record-before-overwrite).
     *
     * INSERT IGNORE 패턴: token_hash UNIQUE 제약 중복 시 silent skip
     * (idempotent 재저장·revoke 재저장 방어).
     *
     * @param id              UUID 문자열 (호출자 생성)
     * @param tokenHash       SHA-256 lowercase hex 64자
     * @param authorizationId oauth2_authorization.id
     * @param consumedAt      소비일시 (Java 호출 측에서 Instant.now(clock) 공급 — timezone 안전)
     * @param expiresAt       만료일시
     */
    fun insert(
        @Param("id") id: String,
        @Param("tokenHash") tokenHash: String,
        @Param("authorizationId") authorizationId: String,
        @Param("consumedAt") consumedAt: Instant,
        @Param("expiresAt") expiresAt: Instant,
    )
}
