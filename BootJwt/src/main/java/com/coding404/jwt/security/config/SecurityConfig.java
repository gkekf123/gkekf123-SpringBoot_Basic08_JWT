package com.coding404.jwt.security.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.coding404.jwt.security.filter.CustomLoginFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	// 비밀번호 암호화 객체
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		//기본로그인 방식, 세션, 베이직인증, csrf토큰 전부 사용하지 x
		http.csrf().disable();
		
		http.formLogin().disable(); //form기반 로그인을 사용하지 x
		http.httpBasic().disable(); //Authorization: 아이디 형식으로 넘어오는 basic인증을 사용하지 x 		
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //세션인증 기반을 사용하지 않고, JWT사용해서 인증
		
		http.authorizeHttpRequests( auth -> auth.anyRequest().permitAll() ); //모든 요청은 전부 허용
		
		//1. 크로스오리진 필터 생성 cors
		http.cors( Customizer.withDefaults()  );
		
		
		//2. 필터체이닝 연습
		//http.addFilter(new FilterOne() ); //시큐리티타입의 필터를 등록할 때
		
		//http.addFilterBefore(new FilterOne(), UsernamePasswordAuthenticationFilter.class );
		//http.addFilterBefore(new FilterTwo(), FilterOne.class);  //filterOne보다 이전에 등록
		//http.addFilterAfter(new FilterTwo(), FilterOne.class); //filterOne보다 이후에 등록
		
		
		// 3. 로그인 시도에 AuthenticationManager가 필요
		// ++UserDetilaService객체 and PasswoedEncoder가 반드시 필요
		AuthenticationManager authenticationManager =  authenticationManager(http.getSharedObject(AuthenticationConfiguration.class));
		
		// 4. 로그인 필터를 등록
		http.addFilter(new CustomLoginFilter(authenticationManager));
		
		
		
		return http.build();
	}
	
	// f로그인 시도에 필요한 AuthenticationManager 객체
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}
	
	//크로스오리진 필터
	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		//configuration.setAllowedOrigins(Arrays.asList("http://example.com"));
		configuration.setAllowedOrigins(Arrays.asList("*")); //모든 요청에대해서 허용
		configuration.setAllowedMethods(Arrays.asList("*")); //모든 요청메서드를 허용함
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration); //모든 요청에 대해서
		return source;
	}
	
	
	
	
	
	
	
	
	
	
	
}
