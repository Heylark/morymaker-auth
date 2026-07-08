package kr.co.morymaker.auth.persistence.adapter.persistence.refresh

import kr.co.morymaker.auth.application.port.out.refresh.ConsumedRefreshTokenPort
import kr.co.morymaker.auth.domain.refresh.ConsumedRefreshToken
import kr.co.morymaker.auth.persistence.adapter.persistence.refresh.mapper.ConsumedRefreshTokenMapper
import org.springframework.stereotype.Component
import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * [ConsumedRefreshTokenPort] port-out 구현체 — MyBatis 매퍼 위임 (consumed-hash 레지스트리를 DB에 durable
 * 저장해 재기동 후에도 재사용 탐지가 유지되도록 하는 설계 선택).
 *
 * 헥사고날 레이어: Persistence (adapter).
 * `internal`: application 계층은 [ConsumedRefreshTokenPort] 인터페이스에만 의존한다.
 *             이 클래스를 module-persistence 외부에서 직접 참조하는 것은 금지된다 (레이어 의존 방향 위반).
 *
 * ## 평면 테이블 → 직접 매핑
 * consumed_refresh_tokens는 nested collection이 없는 평면 테이블이다.
 * BaseResultMap이 [ConsumedRefreshToken] 불변 data class로 직접 매핑.
 *
 * ## fail-CLOSED 계약 이행
 * [record]는 매퍼의 INSERT 예외를 그대로 전파한다. catch-and-ignore 금지.
 * 저장 실패 → 예외 전파 → 호출자(Decorator save())의 트랜잭션 롤백 → rotation 전체 실패.
 *
 * ## UUID PK 생성 (record)
 * consumed_refresh_tokens.id는 UUID CHAR(36) — 전 PK UUID 컨벤션.
 * [UUID.randomUUID]로 어댑터가 생성하여 매퍼에 전달한다.
 * [ConsumedRefreshToken] VO는 id 필드를 가지지 않으므로 도메인 계층에 노출되지 않는다.
 *
 * ## timezone 안전 (clock 공급 — [findConsumed] + [record])
 * [findConsumed]: fetchByHash의 lazy-evict 필터(`expires_at > #{now}`)에 `Instant.now(clock)`을
 *   전달한다. DB 서버 `NOW()` 비사용 — MariaDB DATETIME(timezone 미포함) + JDBC serverTimezone
 *   미설정 환경에서 오프셋이 발생하여 live 해시가 만료 오판되는 fail-OPEN을 방지.
 * [record]: consumed_at에도 동일한 [clock]에서 `Instant.now(clock)`을 공급한다.
 * [Clock.systemUTC]를 기본으로 주입하여 테스트에서 fixed clock으로 교체 가능하다.
 *
 * @param consumedRefreshTokenMapper consumed_refresh_tokens DML 매퍼
 * @param clock                      시각 공급 시계 (프로덕션: [Clock.systemUTC], 테스트: fixed clock)
 */
@Component
internal class ConsumedRefreshTokenPersistenceAdapter(
    private val consumedRefreshTokenMapper: ConsumedRefreshTokenMapper,
    private val clock: Clock = Clock.systemUTC(),
) : ConsumedRefreshTokenPort {

    // ── 조회 ──────────────────────────────────────────────────────────────

    /**
     * lazy-evict 필터 포함 조회 — 만료 항목은 DB 쿼리 수준에서 자연 제외.
     *
     * `now`를 명시적으로 전달하여 DB 서버 NOW() timezone 오프셋을 회피한다.
     * [clock]에서 공급된 `Instant.now(clock)`은 항상 UTC 기준이라 timezone 안전.
     */
    override fun findConsumed(tokenHash: String): ConsumedRefreshToken? {
        return consumedRefreshTokenMapper.fetchByHash(tokenHash, Instant.now(clock))
    }

    // ── 저장 ──────────────────────────────────────────────────────────────

    /**
     * fail-CLOSED: INSERT 실패 시 예외를 그대로 전파한다.
     * catch-and-ignore는 rotation의 record-before-overwrite 불변식을 깬다.
     *
     * id: UUID.randomUUID() 생성 — DB PK 컨벤션 (UUID CHAR(36)).
     * consumed_at: [clock]에서 [Instant.now]로 공급 (DB NOW() 비사용 — timezone 안전).
     */
    override fun record(tokenHash: String, authorizationId: String, expiresAt: Instant) {
        consumedRefreshTokenMapper.insert(
            id = UUID.randomUUID().toString(),
            tokenHash = tokenHash,
            authorizationId = authorizationId,
            consumedAt = Instant.now(clock),
            expiresAt = expiresAt,
        )
    }
}
