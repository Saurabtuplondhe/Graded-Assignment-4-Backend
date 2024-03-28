package com.greatlearning.employeemanagement.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {
	
	@GetMapping("/")
	public String handleWelcome() {
		return "<h1>Welcome to Employee Management Web Application</h1>";
	}
}
