package com.swift.microgateway.swift_microgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = { SecurityAutoConfiguration.class })
public class SwiftMicrogatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(SwiftMicrogatewayApplication.class, args);
	}

}
