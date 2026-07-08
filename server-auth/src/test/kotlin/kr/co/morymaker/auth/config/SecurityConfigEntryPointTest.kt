package kr.co.morymaker.auth.config

import org.hamcrest.Matchers.containsString
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder

/**
 * `/oauth2/authorize` 미인증 요청의 매체 타입(Accept)별 엔트리포인트 분기 회귀 테스트.
 *
 * [SecurityConfig] `@Order(1)` 체인은 `MediaTypeRequestMatcher(TEXT_HTML)` 조건부 `LoginUrlAuthenticationEntryPoint`를
 * 등록하지만, Spring `ExceptionHandlingConfigurer`는 entry-point 매핑이 1개뿐이면 matcher를 버리고 그 1개를
 * 무조건 사용한다 — `oauth2ResourceServer { it.jwt {} }`가 `BearerTokenAuthenticationEntryPoint`를 2번째 매핑으로
 * 등록해야 비로소 matcher가 동작한다(SecurityConfig KDoc "WHY" 참조). 이 두 번째 매핑을 실수로 제거하면
 * 비-HTML(API) 요청도 302 `/login`으로 뒤집히는데, 이 회귀를 실제 필터체인으로 방어한다.
 *
 * 인가 프로토콜 파라미터(response_type/client_id/redirect_uri/code_challenge)는 모두 유효하게 채운다 — 이 중
 * 하나라도 빠지면 `OAuth2AuthorizationEndpointFilter`가 인증 여부와 무관하게 client `redirect_uri`로 프로토콜
 * 오류를 리다이렉트한다(RFC 6749 오류 응답 — 매체 타입 엔트리포인트 분기와 무관한 별도 경로이므로 이 테스트가
 * 검증하는 대상이 아니다).
 *
 * 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다(다른 `@SpringBootTest` 클래스와 동일 전제) —
 * `RegisteredClientSeeder`가 기동 시 시딩한 web 클라이언트를 그대로 재사용하므로 DB 쓰기는 없다.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigEntryPointTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var authProperties: AuthProperties

    /**
     * ## WHY — 쿼리 파라미터를 URI 문자열에 직접 인코딩한다(`.param()` 미사용)
     * Spring Authorization Server의 `OAuth2AuthorizationCodeRequestAuthenticationConverter`는
     * GET 요청 파라미터를 `request.getParameterMap()`이 아니라 **`request.getQueryString()` 원문에
     * 해당 키가 실제로 포함되는지**로 다시 걸러낸다(`OAuth2EndpointUtils.getQueryParameters`).
     * `MockHttpServletRequestBuilder.param()`은 파라미터 맵은 채우지만 raw 쿼리 문자열을 항상
     * 채우지는 않아 이 필터에 전부 걸러지고 "response_type 누락"으로 오판된다 — 완전한 쿼리 문자열을
     * 가진 URI를 직접 구성해 호출해야 실제 브라우저/curl 요청과 동일한 경로를 탄다.
     */
    private fun performAuthorize(acceptHeader: String): ResultActions {
        val uri = UriComponentsBuilder.fromPath("/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", authProperties.webClient.clientId)
            .queryParam("redirect_uri", authProperties.webClient.redirectUris.split(",").first().trim())
            .queryParam("scope", "openid")
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .queryParam("code_challenge_method", "S256")
            .build()
            .encode()
            .toUri()
        return mockMvc.perform(get(uri).header("Accept", acceptHeader))
    }

    @Test
    fun `미인증 비-HTML(API) 요청은 401을 받는다 (302로 뒤집히지 않음)`() {
        performAuthorize(MediaType.APPLICATION_JSON_VALUE)
            .andExpect(status().isUnauthorized)
            .andExpect(header().string("WWW-Authenticate", containsString("Bearer")))
    }

    @Test
    fun `미인증 브라우저(HTML) 요청은 login 페이지로 302 리다이렉트된다`() {
        performAuthorize(MediaType.TEXT_HTML_VALUE)
            .andExpect(status().is3xxRedirection)
            .andExpect(header().string("Location", containsString("/login")))
    }
}
