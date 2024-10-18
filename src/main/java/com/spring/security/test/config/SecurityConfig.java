package com.spring.security.test.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public UserDetailsService userDetailsService() {
		
		UserDetails normalUser = org.springframework.security.core.userdetails.User
				.withUsername("normal")
				.password(passwordEncoder().encode("normal"))
				.roles("NORMAL")
				.build();
		
		UserDetails adminUser = org.springframework.security.core.userdetails.User
				.withUsername("admin")
				.password(passwordEncoder().encode("admin"))
				.roles("ADMIN")
				.build();
		
//		 InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager();
//		return inMemoryUserDetailsManager;

		return new InMemoryUserDetailsManager(normalUser, adminUser);
		
	}

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable()
            .authorizeHttpRequests()
//            or we can authorize roles directly in the controller using @PreAuthorize("hasRole('ADMIN')")
//            .requestMatchers("/home/admin")
//            .hasRole("ADMIN")
//            .requestMatchers("/home/normal")
//            .hasRole("NORMAl")
//            .requestMatchers("/home/public")
//            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .formLogin();
        
        return httpSecurity.build();
    }
}