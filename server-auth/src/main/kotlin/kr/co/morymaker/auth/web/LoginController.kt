package kr.co.morymaker.auth.web

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

/**
 * 브랜딩 로그인 페이지 뷰 컨트롤러 — 커스텀 loginPage("/login") 지정으로
 * DefaultLoginPageGeneratingFilter가 제거되므로 GET /login을 직접 렌더한다.
 * ?error·?logout 상태는 템플릿이 ${param.*}로 직접 읽으므로 모델/파라미터가 없다(뷰 전용).
 * 인증·계정 조회는 SecurityConfig의 AuthenticationManager가 담당 — 이 컨트롤러는 서비스·매퍼에 의존하지 않는다.
 */
@Controller
class LoginController {
    @GetMapping("/login")
    fun login(): String = "login"

    // direct 접근(OIDC SavedRequest 부재)으로 로그인 성공 시 기본 successHandler가 '/'로 보내는데
    // auth엔 '/' 핸들러가 없어 404가 났다. 이 매핑은 그 404를 막는 방어선이다 — SavedRequest 소실
    // 자체의 근본 해결은 프록시 X-Forwarded-Proto 주입이고, 여기는 direct 진입의 랜딩만 담당한다.
    // 미인증 '/'는 보안 필터의 로그인 entryPoint가 먼저 가로채므로 이 매핑은 인증된 요청에만 닿는다(표면 불변).
    @GetMapping("/")
    fun root(): String = "redirect:/login"
}
