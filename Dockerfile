FROM eclipse-temurin:17-jdk-alpine
COPY build/libs/*.jar mym-user-authentication-service.jar
ENTRYPOINT ["java", "-jar", "/mym-user-authentication-service.jar"]