package kr.co.morymaker.auth.config

import kr.co.morymaker.auth.application.port.`in`.account.AccountUseCase
import kr.co.morymaker.auth.application.port.out.event.EventScopePort
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer

/**
 * 발급되는 JWT에 RBAC claim(access token)과 event 스코프 claim(access token)·email claim(id token)을 주입한다.
 *
 * ## event_ids — 스칼라(org_id)가 아니라 배열 구조 변경
 * yulse `OrgContextPort.resolveOrgContext`(단일 org)를 그대로 옮기지 않는다. morymaker 계정은 여러 행사를
 * 동시에 담당할 수 있어 [EventScopePort.resolveEventIds]가 배열(`List<String>?`)을 반환한다. null이면
 * SYSTEM_ADMIN(전체 허용)이라는 뜻으로 claim 자체를 생략한다 — 빈 배열과 의미가 다르다(빈 배열은
 * "역할은 있지만 아직 배정된 행사가 0건"). 요청한 event_id가 이 배열 범위 안인지 실제로 강제하는 것은
 * 이 서버의 책임이 아니라 api의 EventScopeGuard가 담당한다 — auth는 발급까지만 책임진다.
 *
 * ## roles/authorities — RBAC B(account.role 단일 컬럼)
 * [kr.co.morymaker.auth.infrastructure.CustomUserDetailsService]가 이미 principal에 `ROLE_${role}`
 * 1개만 적재해 두므로, 이 커스터마이저는 그 authorities를 그대로 옮기기만 한다(2차 DB 조회 없음).
 * `authorities`(permission 코드)는 RBAC B 특성상 항상 빈 목록이다(permission 세분화 도입 전까지).
 *
 * ## email — ID 토큰 전용, scope-gated (access token에는 절대 포함하지 않음)
 * email은 identity claim이라 access token(인가 전용)에 섞지 않는다. `email` scope 인가 시에만 발행하고,
 * 계정 email이 null이면 claim 자체를 생략한다(fail-safe — null 값 발행 금지, CWE-532: 값 자체를
 * 로그에 남기지 않는다).
 *
 * client_credentials 그랜트는 이번 배포에서 미사용(단일 web 클라이언트, authorization_code+PKCE만) —
 * `principal.name`은 항상 계정 UUID이므로 yulse처럼 userId==null 분기를 두지 않는다.
 *
 * @param eventScopePort 토큰 발급 시점 event 스코프 조회 port-out (mint-time DB 조회)
 * @param accountUseCase 본인 email mint-time 조회 (ID_TOKEN email claim)
 */
@Configuration
class TokenCustomizerConfig(
    private val eventScopePort: EventScopePort,
    private val accountUseCase: AccountUseCase,
) {

    @Bean
    fun tokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> =
        OAuth2TokenCustomizer { context ->
            val principal = context.getPrincipal<Authentication>()
            val accountId = principal.name

            // ── ID_TOKEN email claim (scope-gated) ──
            // identity claim은 ID 토큰에만 둔다(access token = 인가 전용 — 분리). email scope 인가
            // 시에만 발행하고, 계정을 못 찾거나 email이 null이면 claim 자체를 생략한다(fail-safe).
            if (context.tokenType.value == OAuth2TokenType("id_token").value &&
                context.authorizedScopes.contains("email")
            ) {
                accountUseCase.findById(accountId)?.email?.let { email ->
                    context.claims.claim("email", email)
                }
            }

            // access token만 대상. id token·refresh 등 다른 타입은 이 아래 claim을 손대지 않는다.
            if (context.tokenType.value != OAuth2TokenType.ACCESS_TOKEN.value) {
                return@OAuth2TokenCustomizer
            }

            val authorities: Collection<GrantedAuthority> = principal.authorities

            // ROLE_ prefix → roles claim (prefix 제거한 역할 코드)
            val roles = authorities.map { it.authority }
                .filter { it.startsWith("ROLE_") }
                .map { it.removePrefix("ROLE_") }

            // ROLE_ 아닌 것 → authorities claim (permission 코드, RBAC B에서는 항상 빈 목록)
            val permissions = authorities.map { it.authority }
                .filter { !it.startsWith("ROLE_") }

            context.claims.claim("roles", roles)
            context.claims.claim("authorities", permissions)
            // sub = principalName(accountId) — SAS 기본 적용, override 불요.

            // ── event_ids (mint-time DB 조회, null=SYSTEM_ADMIN → claim 생략) ──
            eventScopePort.resolveEventIds(accountId)?.let { eventIds ->
                context.claims.claim("event_ids", eventIds)
            }
        }
}
