package kr.co.morymaker.auth

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
class AuthApplicationTests {

    @Test
    fun `Spring 컨텍스트가 정상 로드된다`() {
        // in-memory SAS(RegisteredClientRepository·JWKSource) + module-persistence 미배선(DB 독립 기동) 상태에서
        // 컨텍스트 로드 자체가 성공하는지 검증.
    }
}
