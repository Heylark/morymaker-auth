package kr.co.morymaker.auth.persistence.adapter.persistence.account.mapper

import kr.co.morymaker.auth.domain.account.Account
import org.apache.ibatis.annotations.Mapper
import org.apache.ibatis.annotations.Param
import java.time.Instant

/**
 * account 테이블 MyBatis 매퍼 인터페이스.
 *
 * 헥사고날 레이어: persistence(mapper) — DB 관심사만 담당. 컬럼명 기반 명시 매핑
 * (positional index — 번호로 컬럼을 꺼내는 방식 — 금지: 컬럼 순서 변경 시 조용히 오매핑됨).
 *
 * XML 정의: resources/mapper/account/AccountMapper.xml
 *
 * RBAC B(account.role 단일 컬럼) — JOIN·nested `<collection>` 없음(단일 테이블 조회, 별도 Row DTO 불요).
 * [Account]는 불변이지만 data class가 아니다(passwordHash 로그 노출 방지 위해 toString 직접 오버라이드
 * — domain/account/Account.kt 참조) — `<constructor>` resultMap은 리플렉션 기반 생성자 매핑이라
 * data class 여부와 무관하게 동작한다.
 */
@Mapper
interface AccountMapper {

    /** 로그인 진입점 — email 단건 조회. utf8mb4_unicode_ci 콜레이션이 대소문자 무시 비교를 보장한다. */
    fun selectByEmail(@Param("email") email: String): Account?

    /** id_token email claim 등 경량 조회 + 로그인 성공 기록(recordLoginSuccess) 재조회 경로. */
    fun selectById(@Param("id") id: String): Account?

    /** event 스코프 판정용 경량 role 조회 (EventScopePersistenceAdapter가 사용). */
    fun selectRoleById(@Param("id") id: String): String?

    /**
     * 로그인 시도 결과([Account] 잠금 상태 전이)만 반영하는 좁은 UPDATE — 계정 생성·프로필 수정
     * API가 아니다(AccountPort.save KDoc 참조).
     *
     * @return 갱신된 행 수(0이면 해당 id의 계정이 존재하지 않음 — 호출자가 이미 findById/
     *         findByEmail로 존재를 확인한 뒤 호출하므로 정상 경로에서는 항상 1)
     */
    fun update(
        @Param("id") id: String,
        @Param("failedAttempts") failedAttempts: Int,
        @Param("lockedAt") lockedAt: Instant?,
        @Param("lockedUntil") lockedUntil: Instant?,
    ): Int
}
