// server-auth/build.gradle.kts
// boot 앱 — module-persistence까지 배선(durable JDBC 저장 활성화).
// module-persistence가 api(project(":module-application"))로 선언돼 있어 application·domain 전이도 함께 확보된다.
// 이 배선으로 spring-boot-starter-jdbc·MyBatis·Flyway·MariaDB 드라이버가 boot classpath에 진입해
// DataSource autoconfig가 발동한다 — 로컬 기동 시 MariaDB 선행 필요.
dependencies {
    implementation(project(":module-persistence"))

    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf") // 브랜딩 로그인 페이지 렌더(CSRF 토큰 서버 주입 필수 — 정적 HTML 불가)
    // §3 어드민 REST DTO(@field:NotBlank/@field:Email) 런타임 검증 — 이 검증기 없으면 @Valid가 조용히 무시된다.
    implementation("org.springframework.boot:spring-boot-starter-validation")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
}
