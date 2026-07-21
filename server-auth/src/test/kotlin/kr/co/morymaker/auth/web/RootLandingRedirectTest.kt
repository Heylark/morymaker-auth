package kr.co.morymaker.auth.web

import org.hamcrest.Matchers.containsString
import org.junit.jupiter.api.Test
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.beans.factory.annotation.Autowired

/**
 * direct 접근(OIDC SavedRequest 부재) graceful landing 회귀 가드.
 *
 * 이전에는 인증된 `GET /`에 컨트롤러 핸들러가 없어 `NoResourceFoundException` → 404 JSON이
 * 노출됐다(로그인 직후 direct 케이스·인증된 사용자의 루트 직접 접근 둘 다). `LoginController.root()`
 * 매핑 추가로 `/login`으로 보내 404를 소거한다 — 진짜 SavedRequest 소실 자체의 근본 해결은
 * X-Forwarded-Proto 복원([ForwardedHeaderSchemeIntegrationTest])이고, 이 매핑은 방어선일 뿐이다.
 *
 * 미인증 케이스는 scheme 무관하게 기존 entryPoint가 컨트롤러 도달 전에 이미 `/login`으로 가로채므로
 * (SecurityConfig 무변경) permitAll 확대 없이도 성립함을 보여주는 표면 불변 증거다 — 실 HTTP·scheme
 * 재현이 필요 없어 MockMvc로 충분하다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class RootLandingRedirectTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun `인증된 GET 루트는 login으로 리다이렉트된다`() {
        mockMvc.perform(get("/").with(user("root-landing@morymaker.co.kr").roles("EVENT_ADMIN")))
            .andExpect(status().is3xxRedirection)
            .andExpect(header().string("Location", containsString("/login")))
    }

    @Test
    fun `미인증 GET 루트도 login으로 리다이렉트된다 (인증 표면 불변 증거)`() {
        mockMvc.perform(get("/"))
            .andExpect(status().is3xxRedirection)
            .andExpect(header().string("Location", containsString("/login")))
    }
}
