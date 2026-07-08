// server-auth/build.gradle.kts
// boot 앱 — module-application까지만 소비, module-persistence는 미배선 (DB 독립 기동).
// SAS는 in-memory 모드(RegisteredClientRepository·JWKSource in-memory)로 부트한다 — durable JDBC 저장은 후속 인증 서버 구축 단계로 미룬다.
dependencies {
    implementation(project(":module-application"))

    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
    implementation("org.springframework.boot:spring-boot-starter-actuator")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
}
