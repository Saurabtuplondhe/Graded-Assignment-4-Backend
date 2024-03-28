package com.greatlearning.employeemanagement.service;

import com.greatlearning.employeemanagement.domain.entity.Employee;

public interface EmployeeUpdateService {

	Employee updateExistingEmployee(int id, String firstName, String lastName, String email);

}