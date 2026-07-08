package kr.co.morymaker.auth.domain.account

/**
 * 역할 상수 + Spring Security SpEL 표현식 (yulse `RoleConstants` 패턴 재활용 — 값만 3역할).
 *
 * 헥사고날 레이어: Domain. `@PreAuthorize` 등에서 하드코딩 없이 참조한다(server-auth·api 공용).
 * 세밀 permission 코드는 도입하지 않는다 — RBAC B(account.role 단일 컬럼) 결정에 따라 역할 3개가
 * 고정이므로 `hasAnyRole`을 1차 게이트로 사용한다(과잉 설계 금지).
 */
object MoryRoles {
    const val SYSTEM_ADMIN = "SYSTEM_ADMIN"
    const val EVENT_ADMIN = "EVENT_ADMIN"
    const val EVENT_STAFF = "EVENT_STAFF"

    /** 관리자 콘솔 진입 (실행자 제외). */
    const val HAS_ADMIN_CONSOLE = "hasAnyRole('SYSTEM_ADMIN','EVENT_ADMIN')"

    /** 시스템 관리 전용 (행사 생성·계정 관리). */
    const val HAS_SYSTEM_ADMIN = "hasRole('SYSTEM_ADMIN')"

    /** 실행자 웹 + 관리자 (행사 스코프 검증은 컨트롤러/서비스 계층 별도 — api EventScopeGuard 몫). */
    const val HAS_EVENT_ACCESS = "hasAnyRole('SYSTEM_ADMIN','EVENT_ADMIN','EVENT_STAFF')"
}
