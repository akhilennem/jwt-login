FROM openjdk:8
EXPOSE 8991
ADD target/spring-boot-login-example.jar spring-boot-login-example.jar
ENTRYPOINT ["java","-jar","/spring-boot-login-example.jar"]