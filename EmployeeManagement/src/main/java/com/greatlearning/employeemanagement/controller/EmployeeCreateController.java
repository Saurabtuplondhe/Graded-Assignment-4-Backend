package com.greatlearning.employeemanagement.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.greatlearning.employeemanagement.domain.entity.Employee;
import com.greatlearning.employeemanagement.service.EmployeeCreateService;

@RestController
@RequestMapping("/createService")
public class EmployeeCreateController {
	
	@Autowired
	EmployeeCreateService employeeCreateService;
	
	@PostMapping("/addNewEmployees")
	public String addNewEmployees(@RequestBody List<Employee> employees) {
		return employeeCreateService.addNewEmployees(employees);
	}
}
