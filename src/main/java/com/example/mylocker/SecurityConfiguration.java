package com.example.mylocker;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@EnableWebSecurity // именно здесь будут задаваться проверки доступа к разным url приложения
@Configuration // методы этого класса являются источниками
// конфигурационных Bean-ов
public class SecurityConfiguration {

    @Bean
    public static NoOpPasswordEncoder getEncoder()
    {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }

    // SecurityFilterChain
    // пропускать или нет запрос на этот урл
    // в зависимости от пользователя, его роли, является ли доступ анонимным или
    // пользователь уже аутентифицировался
    // + доп настройки - формы для аутентификации,
    // как делать logout и тп
    @Bean
    public SecurityFilterChain getChain(HttpSecurity http) throws Exception{
        http
                .authorizeHttpRequests(
                        auth ->
                                auth
                                        .requestMatchers(toH2Console()).permitAll()
                                        .requestMatchers("/h2-console/**").permitAll()
                                        .requestMatchers(HttpMethod.GET, "/index.html", "/", "/open", "/h2-console**").permitAll()
                                        .requestMatchers(HttpMethod.GET, "/logout.html", "/secure").authenticated()
                                        .requestMatchers(HttpMethod.GET, "/admin/**").hasAnyRole("ADMIN")
                                        .anyRequest().authenticated()
                )
                .formLogin()
                .and()
                .csrf().disable()
                .headers().frameOptions().disable()
                .and()
                .httpBasic(Customizer.withDefaults())
                .logout() //     POST /logout
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
        ;
        return http.build();
    }

 //   @Bean // источник данных о пользоваелях/паролях,
   // хранящий их в памяти приложения
  //  public InMemoryUserDetailsManager getManager()
  //  {
     //   UserDetails admin = User.withUsername("admin")
    //            .password("admin")
    //            .roles("ADMIN", "BOSS")
    //            .build();

    //    UserDetails user = User.withUsername("user")
    //           .password("user")
   //             .roles("USERS")
    //            .build();

    //    return new InMemoryUserDetailsManager(admin, user);
  // }

    @Bean
    public MyUserDetailsService userDetailsService()
    {
        return new MyUserDetailsService();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider()
    {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(getEncoder());
        provider.setUserDetailsService(userDetailsService());
        return provider;
    }

}
