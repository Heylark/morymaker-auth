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
}
