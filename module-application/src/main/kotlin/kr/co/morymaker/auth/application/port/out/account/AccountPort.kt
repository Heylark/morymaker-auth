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
 *
 * ## 어드민 CRUD 5메서드([insert]~[count]) — 이 REQ에서 신설
 * 위 KDoc이 명시했던 "계정 생성·삭제·프로필 변경 API는 범위 밖"이 이 REQ(관리자 콘솔 API)에서
 * 해소된다. [save]는 잠금 전이 전용 계약을 그대로 유지하고(시그니처 불변), 어드민 쓰기는 전량
 * 새 메서드로 추가한다 — 두 용도를 하나의 메서드로 합치지 않는다(계약 오염 방지).
 */
interface AccountPort {

    fun findByEmail(email: String): Account?

    fun findById(id: String): Account?

    /** event 스코프 판정용 경량 role 조회 (`EventScopePersistenceAdapter`가 사용). */
    fun findRoleById(id: String): String?

    /** 로그인 시도 결과([Account] 잠금 상태 전이)를 저장한다. */
    fun save(account: Account)

    /** 계정 신규 생성(§3-2). email UNIQUE 위반 시 durable 저장소가 `DuplicateKeyException`을 던진다. */
    fun insert(account: Account)

    /** 프로필 갱신(§3-3) — 이름·역할·메모만. email·password·잠금 필드는 건드리지 않는다. */
    fun updateProfile(id: String, name: String?, role: String, note: String?)

    /** 상태 토글(§3-4) — "활성"/"비활성". */
    fun updateStatus(id: String, status: String)

    /** 목록 조회(§3-1) — role/status/q 필터 + 페이징. */
    fun search(search: AccountSearch): List<Account>

    /** 전체 건수(§3-1) — 호출자가 `search.paging=false`로 넘겨야 정확한 전체 건수가 나온다. */
    fun count(search: AccountSearch): Int
}
