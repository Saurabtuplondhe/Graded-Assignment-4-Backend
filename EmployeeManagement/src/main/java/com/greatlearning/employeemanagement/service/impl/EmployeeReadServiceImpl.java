package com.greatlearning.employeemanagement.service.impl;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Service;

import com.greatlearning.employeemanagement.domain.entity.Employee;
import com.greatlearning.employeemanagement.repository.EmployeeRepository;
import com.greatlearning.employeemanagement.service.EmployeeReadService;

@Service
public class EmployeeReadServiceImpl implements EmployeeReadService {
	
	@Autowired
	EmployeeRepository employeeRepository;
	@Override
	public List<Employee> getAllEmployees() {
		return employeeRepository.findAll();
	}
	public Optional<Employee> getEmployeeById(int id) {
		return employeeRepository.findById(id);
		
	}
	
	public List<Employee> findByFirstName(String firstName) {
		Employee employee = new Employee();
		employee.setFirstName(firstName);
		ExampleMatcher exampleMatcher = ExampleMatcher.matching().withMatcher(firstName, ExampleMatcher.GenericPropertyMatchers.exact())
				.withIgnorePaths("id", "email", "lastName");
		Example<Employee> example = Example.of(employee, exampleMatcher);
		return employeeRepository.findAll(example);
	}
	
	public List<Employee> sortByFirstName(Direction direction) 
	{
		return employeeRepository.findAll(Sort.by(direction,"firstName"));
	}
}
