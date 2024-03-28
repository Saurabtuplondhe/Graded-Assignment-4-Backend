package com.greatlearning.employeemanagement.controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.greatlearning.employeemanagement.domain.entity.Employee;
import com.greatlearning.employeemanagement.service.EmployeeReadService;

@RestController
@RequestMapping("/getService")
public class EmployeeReadController {

	@Autowired
	EmployeeReadService employeeReadService;

	@GetMapping("/getAllEmployees")
	
	public List<Employee> getAllEmployees() 
	{
		return employeeReadService.getAllEmployees();
	}
	@GetMapping("/getEmployeeById")
	public Optional<Employee> getEmployeeById(int id) 
	{
		return employeeReadService.getEmployeeById(id);
		
	}
	@GetMapping("/findByFirstName")
	public List<Employee> findByFirstName(String firstName)
	{
		return employeeReadService.findByFirstName(firstName);
	}
	@GetMapping("/sortByFirstName")
	public List<Employee> sortByFirstNAme(Direction direction) 
	{
		return employeeReadService.sortByFirstName(direction);
		
	}
	
	
}
