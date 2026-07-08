package kr.co.morymaker.auth.infrastructure

import kr.co.morymaker.auth.domain.account.Account
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component

/**
 * [Account] → Spring Security authority 변환 (RBAC B — 단일 역할, permission flatten 불요).
 *
 * yulse `UserAuthorityMapper`가 역할+권한 평면화(ROLE_ ∪ permission.code)를 담당했던 것과 달리,
 * morymaker는 `account.role` 단일 컬럼이라 `ROLE_${role}` 1개만 발급한다.
 */
@Component
class AccountAuthorityMapper {

    /** [Account.role] 을 `ROLE_${role}` 단일 권한으로 변환한다(RBAC B — permission 코드 없음). */
    fun map(account: Account): List<GrantedAuthority> =
        listOf(SimpleGrantedAuthority("ROLE_${account.role}"))
}
