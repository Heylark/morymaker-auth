// module-application/build.gradle.kts
dependencies {
    api(project(":module-domain"))

    // Spring Transaction (@Transactional — 유스케이스 계층)
    api("org.springframework:spring-tx")

    // Spring Security Core (권한 체크 예외 타입 등)
    api("org.springframework.security:spring-security-core")

    // Actuator (헬스체크)
    api("org.springframework.boot:spring-boot-starter-actuator")

    // Jakarta Validation (compileOnly)
    compileOnly("jakarta.validation:jakarta.validation-api")
}
