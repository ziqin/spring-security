package org.example.deserializerbug;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@SpringBootApplication
public class DeserializerBugApplication {

	public static void main(String[] args) {
		SpringApplication.run(DeserializerBugApplication.class, args);
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) {
		http
			.formLogin(withDefaults())
			.webAuthn((webAuthn) -> webAuthn
				.rpId("deserializer-bug.localhost")
				.allowedOrigins("http://deserializer-bug.localhost:8080")
			)
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/webauthn/register/**").fullyAuthenticated()
				.requestMatchers("/user.html").authenticated()
				.anyRequest().permitAll()
			);
		return http.build();
	}

	@Bean
	UserDetailsService userDetailsService() {
		UserDetails demoUser = User.withDefaultPasswordEncoder()
			.username("user")
			.password("password")
			.build();
		return new InMemoryUserDetailsManager(demoUser);
	}

}
