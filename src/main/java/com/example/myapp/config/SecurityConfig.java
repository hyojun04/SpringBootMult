package com.example.myapp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.myapp.jwt.JwtAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Autowired
	JwtAuthenticationFilter authenticationFilter;
	
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		http.csrf((csrfConfig) -> csrfConfig.disable());
		
		/*
		 * http.formLogin(login -> login.loginPage("/member/login")
		 * .usernameParameter("userid") .defaultSuccessUrl("/")); http.logout(logout ->
		 * logout.logoutUrl("/member/logout") .logoutSuccessUrl("/member/login")
		 * .invalidateHttpSession(true));
		 */
		
		http.authorizeHttpRequests(authRequest -> authRequest
				.requestMatchers("/file/**").hasRole("ADMIN")
				.requestMatchers("/board/**").hasAnyRole("USER","ADMIN")
				.requestMatchers("/css/**","/js/**","/images/**").permitAll()
				.requestMatchers("/member/insert").permitAll()
				.requestMatchers("/member/login").permitAll()
				.requestMatchers("/**").permitAll());
		
		http.sessionManagement((session)-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		
		http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}
	
	@Bean
	@ConditionalOnMissingBean(UserDetailsService.class)
	InMemoryUserDetailsManager userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withUsername("foo").password("{noop}demo").roles("ADMIN").build(),
				User.withUsername("bar").password("{noop}demo").roles("USER").build(),
				User.withUsername("ted").password("{noop}demo").roles("USER","ADMIN").build()
				);
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
}
