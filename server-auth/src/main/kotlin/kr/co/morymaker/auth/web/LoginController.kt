package kr.co.morymaker.auth.web

import kr.co.morymaker.auth.config.AuthProperties
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

/**
 * 브랜딩 로그인 페이지 뷰 컨트롤러 — 커스텀 loginPage("/login") 지정으로
 * DefaultLoginPageGeneratingFilter가 제거되므로 GET /login을 직접 렌더한다.
 * ?error·?logout 상태는 템플릿이 ${param.*}로 직접 읽으므로 모델/파라미터가 없다(뷰 전용).
 * 인증·계정 조회는 SecurityConfig의 AuthenticationManager가 담당 — 이 컨트롤러는 서비스·매퍼에 의존하지 않는다.
 */
@Controller
class LoginController(
    private val authProperties: AuthProperties,
) {
    private val trustResolver = AuthenticationTrustResolverImpl()

    // 이미 인증된 사용자가 /login에 재접근하면(즐겨찾기 재클릭, 뒤로가기 등) 폼을 다시 보여주지 않고
    // 웹 콘솔로 보낸다. 판정은 "확실할 때만" 웹으로 보내는 fail-open — 애매하면 폼을 렌더하는 쪽으로
    // 넘어진다. 미인증 시 이 파라미터는 null(AnonymousAuthenticationToken 아님, 실측 확인)이지만
    // 그 실측 하나에 방어선을 의존시키지 않도록 isAnonymous 이중 판정을 더한다 — 익명을 인증으로
    // 오판하면 로그인 화면 자체에 못 들어가 로그인이 전면 불가가 되므로, 오판 시 손해가 비대칭이다.
    @GetMapping("/login")
    fun login(authentication: Authentication?): String =
        if (authentication != null && authentication.isAuthenticated && !trustResolver.isAnonymous(authentication)) {
            "redirect:${authProperties.webClient.successLandingUrl}"
        } else {
            "login"
        }

    // direct 접근(OIDC SavedRequest 부재)으로 로그인 성공 시 기본 successHandler가 '/'로 보내는데
    // auth엔 '/' 핸들러가 없어 404가 났다. 이 매핑은 그 404를 막는 방어선이다 — SavedRequest 소실
    // 자체의 근본 해결은 프록시 X-Forwarded-Proto 주입이고, 여기는 direct 진입의 랜딩만 담당한다.
    // 미인증 '/'는 보안 필터의 로그인 entryPoint가 먼저 가로채므로 이 매핑은 인증된 요청에만 닿는다(표면 불변).
    @GetMapping("/")
    fun root(): String = "redirect:/login"
}
