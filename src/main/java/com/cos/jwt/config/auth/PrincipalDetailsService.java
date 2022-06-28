package com.cos.jwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

// http://localhost:8080/login 요청이 오면 동작을 안한다.formlogin().disable 해놔서
// filter에 동작하도록 등록을 해놔야 한다. jwtAuthenticationFilter 생성
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService{
	
	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("PrincipalDetaiolsService의 loadUserByUsername()");
		User userEntity = userRepository.findByUsername(username);
		return new PrincipalDetails(userEntity);
	}
	

}
 