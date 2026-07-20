package kr.co.morymaker.auth.application.port.`in`.account

import kr.co.morymaker.auth.application.port.out.account.AccountSearch
import kr.co.morymaker.auth.application.service.dto.AccountAdminResult
import kr.co.morymaker.auth.application.service.dto.AccountCreateCommand
import kr.co.morymaker.auth.application.service.dto.AccountUpdateCommand

/**
 * 계정 어드민 CRUD 유스케이스(port-in) — spec §3 목록·생성·수정·상태토글(SYSTEM_ADMIN 전용).
 *
 * [AccountUseCase](로그인 진입점 조회 + 잠금 상태 기록)와 의도적으로 분리한다 — 두 인터페이스는
 * 호출자(server-auth의 인가 표면)도, 책임(읽기 전용 인증 흐름 vs 어드민 쓰기)도 다르다.
 */
interface AccountAdminUseCase {

    /** 목록 조회(3-1) — role/status/q 필터 + 페이징. */
    fun list(search: AccountSearch): AccountAdminResult.Page

    /** 계정 생성(3-2) — email 중복(409)·역할별 eventIds 필수(422) 검증 후 자격증명 발급. */
    fun create(command: AccountCreateCommand): AccountAdminResult

    /** 프로필 수정(3-3) — 역할 변경 시 account_event 전량 재작성(delete-insert). */
    fun update(id: String, command: AccountUpdateCommand): AccountAdminResult

    /** 상태 토글(3-4) — 활성/비활성. 비활성은 기존 로그인 차단 연동(CustomUserDetailsService)에 자동 반영. */
    fun toggleStatus(id: String, status: String): AccountAdminResult
}
