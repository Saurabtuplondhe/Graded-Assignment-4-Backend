package com.greatlearning.employeemanagement.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.greatlearning.employeemanagement.domain.entity.Employee;
import com.greatlearning.employeemanagement.repository.EmployeeRepository;
import com.greatlearning.employeemanagement.service.EmployeeUpdateService;

@Service
public class EmployeeUpdateServiceimpl implements EmployeeUpdateService {
	
	@Autowired
	EmployeeRepository updateRepository;
	
	@Override
	public Employee updateExistingEmployee(int id, String firstName, String lastName, String email) {
		if(updateRepository.findById(id).isPresent()) {
			Employee existingEmployee = updateRepository.findById(id).get();
			
			existingEmployee.setFirstName(firstName);
			existingEmployee.setLastName(lastName);
			existingEmployee.setEmail(email);
			
			Employee updatedEmployee = updateRepository.save(existingEmployee);
			
			return new Employee(updatedEmployee.getId(), updatedEmployee.getFirstName(), updatedEmployee.getLastName(),
					updatedEmployee.getEmail());
		}else {
			return null;
		}
	}
}
