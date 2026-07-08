package kr.co.morymaker.auth.application.port.`in`.account

import kr.co.morymaker.auth.domain.account.Account

/**
 * 계정 조회 + 로그인 결과 기록 유스케이스 (port-in).
 *
 * 헥사고날 레이어: Application. server-auth(`CustomUserDetailsService`·로그인 이벤트 리스너)가
 * 이 인터페이스만 의존한다 — 구현체(`AccountService`)는 internal이라 외부 모듈에서 직접 참조할 수 없다.
 *
 * 계정 생성·프로필 수정 등 CRUD는 이 REQ 범위 밖(후속 REQ의 관리자 콘솔 API 몫)이다. 여기 있는
 * 메서드는 ① 인증 진입점 조회 ② 로그인 시도 결과에 따른 잠금 상태 기록, 두 가지 인증 흐름 전용
 * 책임만 진다.
 */
interface AccountUseCase {

    /** 로그인 진입점 — email로 계정 조회. `CustomUserDetailsService`가 사용. */
    fun findByEmail(email: String): Account?

    /** id_token email claim 등 경량 조회. 로그인 성공 기록(recordLoginSuccess)의 재조회 경로로도 사용. */
    fun findById(id: String): Account?

    /**
     * 로그인 실패 1회를 기록한다(잠금 임계 판정 포함 — `Account.recordFailedAttempt`).
     * 존재하지 않는 email이면 아무 것도 하지 않는다 — 계정 존재 여부를 side-effect로 노출하지
     * 않기 위함이다(사용자 열거 방지, 401 응답과 동일하게 무반응).
     */
    fun recordLoginFailure(email: String)

    /** 로그인 성공을 기록한다(실패 횟수·잠금 상태 초기화 — `Account.recordSuccessfulLogin`). */
    fun recordLoginSuccess(accountId: String)
}
