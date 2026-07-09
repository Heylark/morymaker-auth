package kr.co.morymaker.auth.application.service.dto

import kr.co.morymaker.auth.domain.account.Account

/**
 * 어드민 유스케이스 출력(port-in 결과) — [Account] + 조립된 eventIds.
 *
 * CP-2에서 E2는 (a) 관리자 지정 방식으로 확정됐다(서버 자동생성 임시비밀번호 방식(b)은 미채택) —
 * 그래서 이 결과 DTO는 초기 비밀번호를 응답에 실어 보내는 필드를 두지 않는다(YAGNI — (b) 전용
 * 필드를 만들어 두고 항상 null로 남기지 않는다).
 */
data class AccountAdminResult(
    val account: Account,
    val eventIds: List<String>,
) {
    data class Page(
        val items: List<AccountAdminResult>,
        val total: Int,
        val page: Int,
        val size: Int,
    )
}
