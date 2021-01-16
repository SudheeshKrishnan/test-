
package com.bosch.assignment.employee.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder authenticationMgr) throws Exception {
		authenticationMgr.inMemoryAuthentication()
			.withUser("arun").password("arun@123").authorities("ROLE_USER")
			.and()
			.withUser("sudheesh").password("sudi@123").authorities("ROLE_USER","ROLE_ADMIN");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		
		http.authorizeRequests()
			.antMatchers("/employee-service/employee").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
			.antMatchers("/employee-service/payroll").access("hasRole('ROLE_ADMIN')")
			.antMatchers("/employee-service/payroll").access("hasRole('ROLE_ADMIN')")
			.antMatchers("/employee-service/project").access("hasRole('ROLE_ADMIN')")
			.and().csrf().disable();
		
	}
}
