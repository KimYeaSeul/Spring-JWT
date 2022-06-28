package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음.
// /login 요청해서 Username, password 전송하면 (Post로) filter가 동작을 함.
// 근데 지금 formlogin disable해놔서 동작 안함!!
// 따라서 security config 에 다시 등록을 해줘야함.
// authenticationManager 를 넘겨줘서 받아줘야함.
// RequiredArgsConstructor로 받아주었다 와우!
@RequiredArgsConstructor
public class JwtAuthehnticationFIlter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	
	//  로그인 시 시도하는 함수
	// /login 요청을 하면 login시도를 위해서 실행되는 함수.
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthehnticationFIlter : 로그인 시도중");
		// 여기서 로그인 로직 처리하면 됌.!!
		// 1. username, password 받아서
		try {
//			System.out.println(request.getInputStream().toString()); // username과 password를 담고 있다.
			// 아래를 하면 인풋 값 볼 수 있듬.
//			BufferedReader br = request.getReader();
//			
//			String input = null;
//			while((input = br.readLine())!=null) {
//				System.out.println(input);   // username=ssar&password=1234   x-www-form-urlencoded > 일반적인 로그인 방식
			                                                    // {"username":"ssar" , "password":"1234" }  raw : json
//			}
			// 
			ObjectMapper om = new ObjectMapper(); // json데이터를 parsing 해줌. ( json으로 데이터가 들어왔다고 생각하고.. )
			User user = om.readValue(request.getInputStream(), User.class);
//			System.out.println(user); // User(id=0, username=ssar, password=1234, roles=null)
			
			// formLogin하면 자동으로 토큰이 생성 되는데 직접 로그인 시도를 해야해서 직접 토큰을 만들어야함.
			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// 토큰으로 로그인 시도
			// username만 받고 password는 spring이 알아서 처리해줌.
			// PrincipalDetailsService의 LoadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨.
			// db에 있는 Username과 password가 일치한다.
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername()); // 로그인이 정상적으로 되었다는 뜻.
			
			// return 시 authentication 객체가 session영역에 저장 해야하고 그 방법이 return 해주면 됨.
			// 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고.
			// 굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 session넣어 줌.
			
			// JWT토큰을 만들어주자.
			return authentication;
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		// 2. 정상인지 로그인 시도를 해봄.
		// authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출됨.
		// LoadUserByUsername() 이 실행됨
		// 3. PrincipalDetails를 세션에 담고 (권한관리를 위해서)
		//    (안담으면 권한(admin, manager) 관리가 안된다.)
		// 4. JWT 토큰을 만들어서 응답해주면 됨.
//		return super.attemptAuthentication(request, response);
		return null;
	}
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨.
	// 여기서 JWT토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 response 해주면 됨.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 이 실행됨.");
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		// pom.xml에 jwt있음, build up pattern
		// RSA 방식은 아니구 Hash암호 방
		String jwtToken = JWT.create()
				.withSubject("cos토큰") // 이름
				.withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME)) // 만료시간 1000 = 1초, 
				.withClaim("id", principalDetails.getUser().getId())  
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));
		
		response.addHeader("Authorization", "Bearer " + jwtToken);
//		super.successfulAuthentication(request, response, chain, authResult);
	}
}
