package com.attendance.login;

import com.attendance.login.UserPackage.controllers.AuthController;
import com.attendance.login.UserPackage.models.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;


@SpringBootApplication
public class SpringBootLoginExampleApplication {

	@Bean
	public RestTemplate getRestTemplate(){
		return  new RestTemplate();
	}

	public static void main(String[] args) {
		SpringApplication.run(SpringBootLoginExampleApplication.class, args);
	}

//	   @Bean
//	   CommandLineRunner run(AuthController authController){
//        return args -> {
//            authController.addrole(new Role(null,"ROLE_USER"));
//            userService.saveRole(new Role(2,"ROLE_ADMIN"));
//
//        };
//	 }
//
}
