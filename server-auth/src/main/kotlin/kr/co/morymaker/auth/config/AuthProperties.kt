package kr.co.morymaker.auth.config

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

/**
 * `morymaker.auth.*` 설정 바인딩 — OIDC issuer + 부팅 시 멱등 등록할 web 클라이언트 정보.
 *
 * web 클라이언트 값은 [kr.co.morymaker.auth.bootstrap.RegisteredClientSeeder]가 기동 시점에
 * 현재 설정 기준으로 `JdbcRegisteredClientRepository`에 등록·갱신한다(config-authoritative —
 * 클라이언트 관리 콘솔이 stripped된 lite 배포라 config 변경이 유일한 정당 변경 경로).
 */
@ConfigurationProperties("morymaker.auth")
data class AuthProperties(
    /**
     * OAuth2/OIDC issuer URI.
     * 예: http://localhost:30000
     */
    val issuer: String,

    /** 부팅 시 멱등 등록할 단일 web 클라이언트(콘솔·실행자·키오스크·방문자 4표면 공용 SPA). */
    val webClient: WebClientProperties,

    /** refresh rotation 전제 토큰 수명 — [kr.co.morymaker.auth.bootstrap.RegisteredClientSeeder]가 TokenSettings에 배선한다. */
    val tokenPolicy: TokenPolicyProperties,
) {
    data class WebClientProperties(
        val clientId: String,
        val clientSecret: String,
        val redirectUris: String,
        val scopes: String,
        /** SavedRequest 부재 폼 로그인의 기본 착지(웹 콘솔). 하드코딩 금지 — 배포마다 실 도메인. */
        val successLandingUrl: String,
        /** RP-initiated logout 착지 좌표(csv). 등록값과 요청값은 byte-exact 일치해야 한다. */
        val postLogoutRedirectUris: String,
    )

    /**
     * access/refresh 토큰 수명 — 행사 당일 종일 운영(재로그인 없음) 요구사항에 맞춘 확정값.
     * `reuseRefreshTokens=false`(rotation 활성화)는 RFC 9700 §4.14.2 MUST 요구사항이자
     * 재사용 탐지의 성립 전제라 config 노출 대상이 아니라 seeder에 하드코딩한다 — 이 클래스에는
     * TTL 두 값만 둔다.
     */
    data class TokenPolicyProperties(
        val accessTokenTtl: Duration,
        val refreshTokenTtl: Duration,
    )
}
