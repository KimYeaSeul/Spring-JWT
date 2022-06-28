package com.cos.jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthehnticationFIlter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final CorsFilter corsFilter;
	private final UserRepository userRepository;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// config filter보다 security filter가 먼저 실행됨.
		// security filter에 안걸고 따로 빼줌 -> FilterCOnfig.java
//		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);

		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // seession 사용 x , stateless																// server로 사용.
		.and().addFilter(corsFilter) // 인증이 있을 때(로그인 등) 시큐리티 필터에 등록
		.formLogin().disable() // jwt server니까 form login 사용 x
		.httpBasic().disable() // 기본적인 Http 도 안쓰고
		.addFilter(new JwtAuthehnticationFIlter(authenticationManager())) // authenticationManager를 던져줘야함.
		.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository)) //
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')").anyRequest().permitAll();
		// default formlogin 주소 : /login 하지만 위에서 formLogin().disable 해놔서 /login이 동작 안함.
//		.and()
//		.formLogin()
//		.loginProcessingUrl("/login")
	}
}
