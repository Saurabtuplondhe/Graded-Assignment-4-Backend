package com.greatlearning.employeemanagement.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.greatlearning.employeemanagement.domain.entity.Employee;
import com.greatlearning.employeemanagement.repository.EmployeeRepository;
import com.greatlearning.employeemanagement.service.EmployeeCreateService;

@Service
public class EmployeeCreateServiceImpl implements EmployeeCreateService {

	@Autowired
	EmployeeRepository employeeRepository;
	@Override
	public String addNewEmployees(List<Employee> employees) {
		employeeRepository.saveAll(employees);
		employeeRepository.flush();
		return "New Employee Added";
	}
}
