package kr.co.morymaker.auth.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher

/**
 * 인증 서버 SecurityFilterChain — 2체인 구성(AS 프로토콜 + 폼 로그인 catch-all).
 *
 * 골격 단계는 `AuthorizationServerConfig`의 `@Import(OAuth2AuthorizationServerConfiguration)`가
 * 필터체인까지 자동 등록했지만, durable 전환 이후에는 이 클래스가 `@Order(1)` 체인을 직접 소유한다
 * (`applyDefaultSecurity` 명시 호출로 동일 동작을 재현). `AuthorizationServerConfig`의 durable JDBC
 * 빈(등록 클라이언트·인가·동의 저장소·JWT decoder)은 그대로 자동 배선되어 사용된다.
 *
 * 계정 도메인(로그인 사용자 조회)은 아직 이 저장소에 없다 — `@Order(5)` 체인은 폼 로그인의 골격만
 * 갖추고, 실 계정 조회에 연결된 인증 제공자는 계정 도메인이 들어오는 시점에 배선된다.
 */
@Configuration
class SecurityConfig {

    /**
     * `@Order(1)` — SAS 프로토콜 체인 (`/oauth2/` 하위, `/.well-known/openid-configuration`, JWKS 등).
     *
     * `AuthorizationServerConfig`의 durable 빈(JWK·인코더·해시 refresh Decorator·클라이언트 저장소)을
     * 그대로 사용한다(`applyDefaultSecurity`가 자동 배선).
     *
     * ## WHY — EntryPoint 를 [MediaTypeRequestMatcher]`(TEXT_HTML)`로 한정
     * 미인증 요청이 들어오면 브라우저(`Accept: text/html`)는 `/login`으로 302 보내야 하지만,
     * REST 클라이언트(`Accept: application/json`)는 리다이렉트 대신 **401**을 받아야 한다.
     * matcher 없이 `LoginUrlAuthenticationEntryPoint`만 등록하면 JSON 클라이언트도 302 /login 으로 끌려간다.
     *
     * ## WHY — `oauth2ResourceServer { jwt {} }` 가 **필수**
     * Spring `ExceptionHandlingConfigurer`는 entry-point 매핑이 **1개뿐이면 matcher 를 버리고 그 1개를
     * 무조건** 사용한다. 즉 위 HTML matcher 하나만 두면 matcher 가 폐기돼 **모든** 미인증 요청이
     * 302 /login 으로 가버린다(JSON 클라이언트 401 깨짐). `oauth2ResourceServer(jwt)`가
     * `BearerTokenAuthenticationEntryPoint`(비-HTML → 401)를 **2번째 매핑**으로 등록해야 비로소
     * matcher 가 동작한다(HTML→302 /login / 비-HTML→401). `jwtDecoder` 빈이 자동 배선되므로
     * 신규 엔드포인트·추가 설정은 0건이다.
     */
    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        // ★ OIDC(OpenID Connect) 명시 활성화 — `applyDefaultSecurity`는 순수 OAuth2 필터만 등록하고
        // OIDC discovery(`/.well-known/openid-configuration`)·userinfo 엔드포인트 필터는 이 호출 없이는
        // 등록되지 않는다(실측 확인 — DEBUG 필터체인 로그에 OidcProviderConfigurationEndpointFilter 부재).
        // morymaker web 클라이언트는 openid scope로 id_token을 받는 OIDC 흐름이 필수(커스텀 OIDC 인증 모델).
        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
            .oidc(Customizer.withDefaults())
        http.exceptionHandling { exceptions ->
            // ★ MediaTypeRequestMatcher — REST 클라이언트(Accept: json)의 302 리다이렉트 방지(401 반환)
            exceptions.defaultAuthenticationEntryPointFor(
                LoginUrlAuthenticationEntryPoint("/login"),
                MediaTypeRequestMatcher(MediaType.TEXT_HTML),
            )
        }
        // ★★ matcher 활성화 조건(2번째 entry point 공급). 위 KDoc "WHY" 참조. 제거 금지.
        //    (이 줄을 제거하면 비-HTML 요청이 401 → 302 로 뒤집혀 즉시 회귀)
        http.oauth2ResourceServer { it.jwt { } }
        return http.build()
    }

    /**
     * `@Order(5)` — 폼 로그인 catch-all 체인. `/login`(Spring Security 기본 생성 페이지)·헬스체크·
     * discovery permitAll + 나머지 인증 필요.
     *
     * ## WHY — 커스텀 로그인 페이지를 지정하지 않는다
     * 계정 도메인(로그인 사용자 조회 서비스)이 아직 이 배포에 없다 — 커스텀 `loginPage("/login")`을
     * 지정하면 `DefaultLoginPageGeneratingFilter`가 제거되어 별도 로그인 컨트롤러·템플릿 없이는
     * `GET /login`이 404가 된다. 계정 도메인이 들어오는 시점에 커스텀 로그인 페이지·인증 제공자로 교체한다.
     *
     * ## WHY — CSRF 활성 유지
     * 전역 CSRF 면제를 추가하지 않는다(silent loosening 금지 원칙). Spring Security 기본 로그인 폼은
     * same-origin이라 `_csrf` 히든 필드를 자동 포함하므로 폼 로그인은 정상 동작한다.
     */
    @Bean
    @Order(5)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorize ->
                authorize
                    .requestMatchers(
                        "/login", // Spring Security 기본 로그인 폼(GET) + 처리(POST)
                        "/error", // Spring Boot Whitelabel 에러 페이지
                        "/.well-known/**", // OIDC discovery
                        "/actuator/health", // 헬스체크 무인증 200(항상 permitAll 불변 원칙)
                        "/favicon.ico",
                    ).permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin { }
        return http.build()
    }
}
