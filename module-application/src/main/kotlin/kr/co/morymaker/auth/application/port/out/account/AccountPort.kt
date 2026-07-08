package kr.co.morymaker.auth.application.port.out.account

import kr.co.morymaker.auth.domain.account.Account

/**
 * 계정 durable 저장 port-out.
 *
 * 구현: `kr.co.morymaker.auth.persistence.adapter.persistence.account.AccountPersistenceAdapter`
 * (internal @Component — module-persistence).
 *
 * ## [save] 범위
 * 설계는 AccountPort를 읽기 전용(`findByEmail`/`findById`/`findRoleById`)으로 명시했으나, 같은 설계가
 * 승인한 잠금 정책은 `failedAttempts`/`lockedAt`/`lockedUntil` 상태 전이를 durable 저장해야만 성립한다.
 * [save]는 계정 생성·프로필 수정을 위한 범용 upsert가 아니라, 로그인 시도 결과([Account]의 잠금
 * 상태 전이)만 반영하는 좁은 용도로 추가했다 — 계정 생성·삭제·프로필 변경 API는 여전히 이 범위 밖
 * (후속 관리자 콘솔 몫)이다.
 */
interface AccountPort {

    fun findByEmail(email: String): Account?

    fun findById(id: String): Account?

    /** event 스코프 판정용 경량 role 조회 (`EventScopePersistenceAdapter`가 사용). */
    fun findRoleById(id: String): String?

    /** 로그인 시도 결과([Account] 잠금 상태 전이)를 저장한다. */
    fun save(account: Account)
}
