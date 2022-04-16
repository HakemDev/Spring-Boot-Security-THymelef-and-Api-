package com.security.demo;

import com.security.demo.entity.Role;
import com.security.demo.entity.User;
import com.security.demo.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.ArrayList;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	//2
	// create a bean for passwordEncoder
	//whenever the application runs then we will have this bean avalaible
	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	//bean help us to communicate with database to add data
	@Bean
    //here we want add data to database when we load application
	CommandLineRunner run(UserService userService)
	{
		return args->{
			userService.saveRole(new Role(1,"ROLE_USER"));
			userService.saveRole(new Role(2,"ROLE_MANAGER"));
			userService.saveRole(new Role(3,"ROLE_ADMIN"));
			userService.saveRole(new Role(4,"ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(1,"hakem","hakem","1234",new ArrayList<>()));
			userService.saveUser(new User(2,"smith","will","1234",new ArrayList<>()));
			userService.saveUser(new User(3,"carry","jim","1234",new ArrayList<>()));
			userService.saveUser(new User(4,"arnold","schwarzenegger","1234",new ArrayList<>()));

			userService.addRoleToUser("hakem","ROLE_USER");
			userService.addRoleToUser("hakem","ROLE_MANAGER");
			userService.addRoleToUser("will","ROLE_MANAGER");
			userService.addRoleToUser("jim","ROLE_ADMIN");
			userService.addRoleToUser("schwarzenegger","ROLE_USER");
			userService.addRoleToUser("schwarzenegger","ROLE_MANAGER");
			userService.addRoleToUser("schwarzenegger","ROLE_ADMIN");
		};
	}

}
