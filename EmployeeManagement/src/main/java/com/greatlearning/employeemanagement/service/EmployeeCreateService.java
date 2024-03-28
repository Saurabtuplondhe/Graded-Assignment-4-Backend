package com.greatlearning.employeemanagement.service;

import java.util.List;

import com.greatlearning.employeemanagement.domain.entity.Employee;

public interface EmployeeCreateService {

	String addNewEmployees(List<Employee> employees);

}