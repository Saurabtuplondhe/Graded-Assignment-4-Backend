package com.greatlearning.employeemanagement.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.greatlearning.employeemanagement.domain.entity.Employee;
import com.greatlearning.employeemanagement.service.EmployeeUpdateService;

@RestController
@RequestMapping ("/updateService")
public class EmployeeUpdateController {
	@Autowired
	EmployeeUpdateService employeeUpdateService;
	@PostMapping("/updateExistingEmployee")
	public Employee updateExistingEmployee(@RequestParam int id,
			                               @RequestParam  String firstName,
			                               @RequestParam String lastName,
			                               @RequestParam String email) {
		return employeeUpdateService.updateExistingEmployee(id, firstName, lastName, email);
		
	}

}
