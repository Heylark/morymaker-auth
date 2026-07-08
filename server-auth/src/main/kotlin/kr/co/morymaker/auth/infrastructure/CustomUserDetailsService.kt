package kr.co.morymaker.auth.infrastructure

import kr.co.morymaker.auth.application.port.`in`.account.AccountUseCase
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.core.userdetails.User as SpringSecurityUser
import org.springframework.stereotype.Service

/**
 * Spring Security [UserDetailsService] 구현체 — 폼 로그인 인증 진입점.
 *
 * ## stock `SpringSecurityUser` 유지 필수 (커스텀 principal 도입 금지 제약)
 * `SpringSecurityUser`는 커스텀 클래스가 아니라 `org.springframework.security.core.userdetails.User`의
 * import alias다. 커스텀 UserDetails/principal 타입을 도입하면 durable JDBC 인가 저장(Jackson
 * 직렬화)의 allowlist를 깨뜨린다 — 이 클래스는 절대 커스텀 UserDetails 서브클래스를 반환하지 않는다.
 *
 * 보존 계약(Phase 3 `TokenCustomizerConfig`가 의존 — 절대 변경 금지):
 * - `username`(principal) = `account.id`(UUID) — JWT `sub` 안정성
 * - `password` = account.passwordHash (BCrypt)
 * - `enabled` = account.isActive
 * - `accountNonLocked` = !account.isLocked
 * - `authorities` = [AccountAuthorityMapper.map] (RBAC B 단일 역할)
 *
 * 잠금 상태 갱신(로그인 실패/성공 기록)은 이 클래스의 책임이 아니다 — `loadUserByUsername`은
 * 비밀번호 검증 **이전**에 호출되므로 이번 시도의 성공/실패를 알 수 없다. 실제 카운트·잠금 전이는
 * [LoginAttemptListener]가 인증 결과 이벤트에 반응해 처리한다.
 *
 * @param accountUseCase 계정 조회 port-in (persistence 직접 참조 금지)
 * @param accountAuthorityMapper Account → GrantedAuthority 변환 공유 헬퍼
 */
@Service
class CustomUserDetailsService(
    private val accountUseCase: AccountUseCase,
    private val accountAuthorityMapper: AccountAuthorityMapper,
) : UserDetailsService {

    override fun loadUserByUsername(email: String): UserDetails {
        val account = accountUseCase.findByEmail(email)
            ?: throw UsernameNotFoundException("Account not found: $email")

        return SpringSecurityUser(
            account.id,                              // username = UUID (principal — JWT sub)
            account.passwordHash ?: "",               // BCrypt 해시. null이면 빈 문자열 — BCrypt 미매칭으로 인증 불가
            account.isActive,                         // enabled
            true,                                      // accountNonExpired (만료 정책 미도입 — lite)
            true,                                      // credentialsNonExpired (비밀번호 만료 정책 미도입 — lite)
            !account.isLocked,                         // accountNonLocked
            accountAuthorityMapper.map(account),       // ROLE_${role} 1개 (RBAC B)
        )
    }
}
