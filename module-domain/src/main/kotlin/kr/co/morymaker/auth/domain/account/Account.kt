package kr.co.morymaker.auth.domain.account

import java.time.Duration
import java.time.Instant

/**
 * 로그인 계정 도메인 엔티티 — 인증·인가 주체(단일 role, RBAC B).
 *
 * ## 설계 결정: 일반 class + id 기반 equals (data class 아님)
 * `passwordHash`(BCrypt 해시)를 필드로 가지므로, data class의 자동 생성 `toString()`이
 * 해시값을 그대로 로그에 노출할 위험이 있다(CWE-532). `toString()`을 직접 오버라이드해 민감
 * 필드를 배제하고, 동등성은 `id`(불변 PK) 기준으로만 판정한다 — 같은 계정을 가리키는 두 스냅샷은
 * 다른 필드값(예: 갱신 도중)을 가져도 여전히 "같은 계정"이어야 하기 때문이다.
 *
 * ## 상태 전이는 도메인 메서드로 캡슐화
 * [recordFailedAttempt]/[recordSuccessfulLogin]은 잠금 정책(임계치·잠금 기간)에 따라 새 [Account]
 * 스냅샷을 반환한다(불변 전이 — 원본 인스턴스는 변경되지 않음). 호출자(AccountService)는 임계치·
 * 기간 값만 설정에서 읽어 전달하고, 잠금 판정 로직 자체는 이 한 곳에만 존재한다.
 *
 * @param id 계정 PK — JWT `sub`로 전파되는 불변 식별자(UUID). 앱이 생성.
 * @param email 로그인 아이디. DB `utf8mb4_unicode_ci` 콜레이션이 대소문자 무시 비교를 보장한다.
 * @param name 표시 이름 (nullable — 관리자 미기입 허용)
 * @param role SYSTEM_ADMIN / EVENT_ADMIN / EVENT_STAFF ([MoryRoles] 상수 참조)
 * @param status "활성"/"비활성" — 삭제가 아닌 토글([STATUS_ACTIVE] 참조)
 * @param passwordHash BCrypt 해시 (nullable이 아니지만 방어적으로 null 허용 — 매핑 계층 안전)
 * @param failedAttempts 연속 로그인 실패 횟수 — 잠금 판정 기준
 * @param lockedAt 잠금 시작 시각 (null = 잠금 이력 없음)
 * @param lockedUntil 잠금 해제 예정 시각 (null = 미잠금). 경과 시 [isLocked]가 자동으로 false —
 *                     별도 배치·수동 해제 없이 시간 경과만으로 해제된다("최소안").
 * @param note 실행자 담당 위치 등 운영 메모 (nullable)
 * @param createdAt 계정 생성 시각
 */
class Account(
    val id: String,
    val email: String,
    val name: String?,
    val role: String,
    val status: String,
    val passwordHash: String?,
    val failedAttempts: Int,
    val lockedAt: Instant?,
    val lockedUntil: Instant?,
    val note: String?,
    val createdAt: Instant,
) {

    /** 활성 계정 여부 — [kr.co.morymaker.auth.infrastructure.CustomUserDetailsService]의 `enabled` 필드로 사용. */
    val isActive: Boolean
        get() = status == STATUS_ACTIVE

    /**
     * 잠금 여부 — `lockedUntil`이 미래 시각이면 잠금 중.
     * 잠금 기간이 자연 경과하면 별도 배치·해제 API 없이도 이 프로퍼티가 즉시 false로 평가된다.
     */
    val isLocked: Boolean
        get() = lockedUntil?.isAfter(Instant.now()) == true

    /**
     * 로그인 실패를 1회 기록한 새 [Account] 스냅샷을 반환한다.
     *
     * `failedAttempts + 1`이 [maxAttempts] 이상이면 [lockedAt]=now·[lockedUntil]=now+[lockDuration]로
     * 잠금을 새로 건다(또는 연장한다). 이미 잠금 중인데 같은 창 내에서 반복 실패해도 잠금 기간을
     * 매번 다시 연장한다 — 잠금 중 반복 시도는 공격 지속 신호이므로 짧게 유지할 이유가 없다.
     *
     * @param now 기준 시각 (호출자가 공급 — 테스트 결정성 확보, DB 서버 NOW() 비의존)
     * @param maxAttempts 잠금 임계 횟수 (설정값 — 하드코딩 금지)
     * @param lockDuration 잠금 지속 기간 (설정값 — 하드코딩 금지)
     */
    fun recordFailedAttempt(now: Instant, maxAttempts: Int, lockDuration: Duration): Account {
        val attempts = failedAttempts + 1
        val shouldLock = attempts >= maxAttempts
        return Account(
            id = id,
            email = email,
            name = name,
            role = role,
            status = status,
            passwordHash = passwordHash,
            failedAttempts = attempts,
            lockedAt = if (shouldLock) now else lockedAt,
            lockedUntil = if (shouldLock) now.plus(lockDuration) else lockedUntil,
            note = note,
            createdAt = createdAt,
        )
    }

    /**
     * 로그인 성공을 기록한 새 [Account] 스냅샷을 반환한다.
     * 실패 횟수·잠금 상태를 모두 초기화한다(다음 실패 카운트는 0부터 다시 시작).
     */
    fun recordSuccessfulLogin(): Account = Account(
        id = id,
        email = email,
        name = name,
        role = role,
        status = status,
        passwordHash = passwordHash,
        failedAttempts = 0,
        lockedAt = null,
        lockedUntil = null,
        note = note,
        createdAt = createdAt,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Account) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()

    /** passwordHash는 절대 포함하지 않는다 — 로그 출력 시 BCrypt 해시 노출 방지(CWE-532). */
    override fun toString(): String =
        "Account(id=$id, email=$email, role=$role, status=$status, failedAttempts=$failedAttempts, isLocked=$isLocked)"

    companion object {
        const val STATUS_ACTIVE = "활성"
        const val STATUS_INACTIVE = "비활성"
    }
}
