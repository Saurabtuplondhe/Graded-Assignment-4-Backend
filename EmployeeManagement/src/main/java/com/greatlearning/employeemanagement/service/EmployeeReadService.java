package com.greatlearning.employeemanagement.service;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Sort.Direction;

import com.greatlearning.employeemanagement.domain.entity.Employee;

public interface EmployeeReadService {

	List<Employee> getAllEmployees();
	
	Optional<Employee> getEmployeeById(int id);
	
	List<Employee> findByFirstName(String firstName);
	List<Employee> sortByFirstName(Direction direction);

}