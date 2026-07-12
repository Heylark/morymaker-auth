package kr.co.morymaker.auth.web

import org.hamcrest.Matchers.containsString
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.view

/**
 * [LoginController] 뷰 렌더 단위 검증 — `GET /login`이 인증 없이(permitAll) 200과 `login` 뷰를
 * 반환하는지만 확인한다. `SecurityConfig` `@Order(5)` 체인의 `loginPage("/login")` 전환이
 * `DefaultLoginPageGeneratingFilter`(Spring 기본 폼)를 제거한 자리를 이 컨트롤러가 정확히
 * 대체함을 증명한다.
 *
 * OIDC authorize SavedRequest 재개 경로(로그인 성공 후 흐름)는 별도 통합 테스트가 담당한다
 * (Architect 설계 §8-2 SAVEDREQUEST-RESUME — 이 클래스는 GET 렌더 자체만 다룬다).
 *
 * 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다(다른 `@SpringBootTest` 클래스와 동일 전제).
 */
@SpringBootTest
@AutoConfigureMockMvc
class LoginControllerTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun `GET login은 인증 없이 200과 login 뷰를 반환한다`() {
        mockMvc.perform(get("/login"))
            .andExpect(status().isOk)
            .andExpect(view().name("login"))
    }

    @Test
    fun `GET login 응답 본문에 로그인 폼 필드명(username, password)이 포함된다`() {
        mockMvc.perform(get("/login"))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("name=\"username\"")))
            .andExpect(content().string(containsString("name=\"password\"")))
    }

    @Test
    fun `GET login 응답 본문에 모리메이커 브랜딩 마커가 포함되고 Spring 기본 로그인 폼 마커는 없다`() {
        mockMvc.perform(get("/login"))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("Morymaker")))
            .andExpect(content().string(containsString("의전 운영 콘솔")))
            // Spring Boot DefaultLoginPageGeneratingFilter가 생성하는 기본 폼의 고유 문구 —
            // loginPage("/login") 전환 후에도 남아있다면 커스텀 컨트롤러/템플릿이 실제로
            // 그 필터를 대체하지 못했다는 뜻이다.
            .andExpect(content().string(org.hamcrest.Matchers.not(containsString("Please sign in"))))
    }

    @Test
    fun `GET login error 파라미터 시 오류 알림이 렌더되고 logout 알림은 렌더되지 않는다`() {
        mockMvc.perform(get("/login").param("error", ""))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("이메일 또는 비밀번호가 올바르지 않습니다")))
            .andExpect(content().string(org.hamcrest.Matchers.not(containsString("로그아웃되었습니다"))))
    }

    @Test
    fun `GET login logout 파라미터 시 로그아웃 알림이 렌더되고 오류 알림은 렌더되지 않는다`() {
        mockMvc.perform(get("/login").param("logout", ""))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("로그아웃되었습니다")))
            .andExpect(content().string(org.hamcrest.Matchers.not(containsString("이메일 또는 비밀번호가 올바르지 않습니다"))))
    }

    @Test
    fun `GET login 파라미터 없이 요청하면 오류·로그아웃 알림 모두 렌더되지 않는다`() {
        mockMvc.perform(get("/login"))
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.not(containsString("이메일 또는 비밀번호가 올바르지 않습니다"))))
            .andExpect(content().string(org.hamcrest.Matchers.not(containsString("로그아웃되었습니다"))))
    }
}
