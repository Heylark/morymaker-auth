package kr.co.morymaker.auth.application.service.dto

import kr.co.morymaker.auth.domain.account.Account

/**
 * 어드민 유스케이스 출력(port-in 결과) — [Account] + 조립된 eventIds.
 *
 * 초기 비밀번호는 관리자가 직접 지정하고 서버는 강도만 검증하는 방식이라 서버가 값을 생성하지 않는다 —
 * 그래서 이 결과 DTO는 초기 비밀번호를 응답에 실어 보내는 필드를 두지 않는다(서버 자동생성 방식이었다면
 * 필요했을 1회성 응답 필드를 만들어 두고 항상 null로 남기지 않는다).
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
