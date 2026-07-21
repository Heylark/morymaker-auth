package kr.co.morymaker.auth.oauth2

import kr.co.morymaker.auth.config.AuthProperties
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.web.ServerProperties
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.ApplicationContext
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.http.client.SimpleClientHttpRequestFactory
import org.springframework.web.client.RestTemplate
import org.springframework.web.filter.ForwardedHeaderFilter
import org.springframework.web.util.UriComponentsBuilder
import java.net.HttpURLConnection

/**
 * 리버스 프록시 뒤에서 원본 scheme이 올바르게 복원되는지 검증하는 회귀 봉인 테스트.
 *
 * 기존 [LoginSavedRequestResumeIntegrationTest]는 MockMvc 기반이라 실 서블릿 컨테이너·실 HTTP를
 * 거치지 않아 프록시·scheme 바운스를 원리적으로 재현하지 못하고, X-Forwarded-Proto 헤더 자체를
 * 세팅하지도 않으며, 단언 대상도 Location의 경로뿐(scheme은 절대 assert하지 않는다). 이번 배포 장애
 * (mm-accounts vhost가 X-Forwarded-Proto를 안 보내 auth가 http로 오인식 → 로그인 후 절대 redirect가
 * http로 발급 → https↔http 바운스가 세션을 끊어 OIDC SavedRequest가 소실)는 순전히 Location의
 * scheme 좌표 문제라 그 테스트가 보는 좌표(경로)와 완전히 어긋나 구조적으로 놓칠 수밖에 없었다.
 * 이 테스트는 실 HTTP를 띄우는 RANDOM_PORT로 그 scheme 좌표를 직접 검증한다.
 *
 * 리다이렉트를 직접 따라가지 않는 RestTemplate을 별도로 구성해서 쓴다 — 이 모듈엔 Apache HttpClient가
 * 없어 자동 등록되는 `TestRestTemplate`은 JDK `HttpURLConnection` 기반인데, 이 구현체는 같은 프로토콜
 * 리다이렉트(http→http)는 자동으로 따라가면서도 프로토콜이 바뀌는 리다이렉트(http→https)는 따라가지
 * 않는(JDK 보안 정책) 비대칭 동작을 보인다 — 그대로 두면 두 케이스의 검증 조건이 서로 달라져 버린다.
 * `instanceFollowRedirects=false`로 고정해 두 케이스 모두 원본 302 응답을 그대로 받는다.
 *
 * 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다(다른 `@SpringBootTest` 클래스와 동일 전제).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ForwardedHeaderSchemeIntegrationTest {

    @LocalServerPort
    private var port: Int = 0

    @Autowired
    private lateinit var authProperties: AuthProperties

    @Autowired
    private lateinit var serverProperties: ServerProperties

    @Autowired
    private lateinit var applicationContext: ApplicationContext

    private val noRedirectRestTemplate: RestTemplate by lazy {
        val factory = object : SimpleClientHttpRequestFactory() {
            override fun prepareConnection(connection: HttpURLConnection, httpMethod: String) {
                super.prepareConnection(connection, httpMethod)
                connection.instanceFollowRedirects = false
            }
        }
        RestTemplate(factory)
    }

    /** RegisteredClientSeeder가 등록한 web 클라이언트를 대상으로 하는 유효 PKCE authorize 요청 절대 URL. */
    private fun authorizeUrl(): String =
        UriComponentsBuilder.fromHttpUrl("http://localhost:$port/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", authProperties.webClient.clientId)
            .queryParam("redirect_uri", authProperties.webClient.redirectUris.split(",").first().trim())
            .queryParam("scope", "openid")
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .queryParam("code_challenge_method", "S256")
            .build()
            .encode()
            .toUriString()

    @Test
    fun `X-Forwarded-Proto가 https면 authorize 리다이렉트 Location scheme도 https다`() {
        val headers = HttpHeaders()
        headers.set(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
        headers.set("X-Forwarded-Proto", "https")

        val response = noRedirectRestTemplate.exchange(
            authorizeUrl(),
            HttpMethod.GET,
            HttpEntity<Void>(headers),
            String::class.java,
        )

        assertTrue(response.statusCode.is3xxRedirection, "미인증 authorize는 302로 /login에 가로채여야 함")
        val location = response.headers.location
        assertNotNull(location, "Location 헤더 없음")
        assertEquals(
            "https",
            location!!.scheme,
            "핵심 회귀 가드: X-Forwarded-Proto=https를 보냈는데 Location scheme이 https가 아님 — " +
                "ForwardedHeaderFilter가 scheme을 복원하지 못했다는 뜻(mm-accounts vhost XFP 미주입 재현).",
        )
    }

    @Test
    fun `X-Forwarded-Proto 미부여 시 authorize 리다이렉트 Location scheme은 http다 (대조군)`() {
        val headers = HttpHeaders()
        headers.set(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
        // X-Forwarded-Proto 의도적으로 미설정 — 프록시 없는 직접 접근을 모사

        val response = noRedirectRestTemplate.exchange(
            authorizeUrl(),
            HttpMethod.GET,
            HttpEntity<Void>(headers),
            String::class.java,
        )

        assertTrue(response.statusCode.is3xxRedirection)
        val location = response.headers.location
        assertNotNull(location, "Location 헤더 없음")
        assertEquals(
            "http",
            location!!.scheme,
            "대조군 실패 — 헤더를 안 보냈는데도 scheme이 https면 위 메서드의 https 결과가 " +
                "ForwardedHeaderFilter 때문이 아니라 다른 요인(테스트 환경 고정값 등) 때문일 수 있다는 뜻",
        )
    }

    @Test
    fun `forward-headers-strategy가 framework로 바인딩된다`() {
        assertEquals(
            ServerProperties.ForwardHeadersStrategy.FRAMEWORK,
            serverProperties.forwardHeadersStrategy,
            "application.yml의 server.forward-headers-strategy 값이 실제로 바인딩되지 않음",
        )
        // ForwardedHeaderFilter는 FilterRegistrationBean<ForwardedHeaderFilter>로 감싸져 등록되므로
        // 빈 타입 자체는 ForwardedHeaderFilter가 아니라 FilterRegistrationBean이다 — 감싸진 필터를 꺼내 확인한다.
        val registeredForwardedFilter = applicationContext.getBeansOfType(FilterRegistrationBean::class.java)
            .values
            .any { it.filter is ForwardedHeaderFilter }
        assertTrue(
            registeredForwardedFilter,
            "forward-headers-strategy=framework인데 ForwardedHeaderFilter 빈이 등록되지 않음",
        )
    }
}
