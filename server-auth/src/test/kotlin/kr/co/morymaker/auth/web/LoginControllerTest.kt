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
}
