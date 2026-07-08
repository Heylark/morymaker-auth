package kr.co.morymaker.auth

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
class AuthApplicationTests {

    @Test
    fun `Spring 컨텍스트가 정상 로드된다`() {
        // durable JDBC 배선(module-persistence boot 배선) 이후 상태 — DataSource autoconfig가 발동하므로
        // 이 테스트는 로컬 MariaDB(infra/docker-compose.yml)가 기동돼 있어야 통과한다.
        // Flyway 마이그레이션 적용 + RegisteredClientSeeder 실행까지 포함해 컨텍스트 로드 성공 여부를 검증한다.
    }
}
