package com.example.springsocial.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.example.springsocial.security.CustomUserDetailsService;
import com.example.springsocial.security.RestAuthenticationEntryPoint;
import com.example.springsocial.security.TokenAuthenticationFilter;
import com.example.springsocial.security.oauth2.CustomOAuth2UserService;
import com.example.springsocial.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.example.springsocial.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.example.springsocial.security.oauth2.OAuth2AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private CustomUserDetailsService customUserDetailsService;

  @Autowired
  private CustomOAuth2UserService customOAuth2UserService;

  @Autowired
  private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

  @Autowired
  private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

  @Autowired
  private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

  @Bean
  public TokenAuthenticationFilter tokenAuthenticationFilter() {
    return new TokenAuthenticationFilter();
  }

  /*
   * By default, Spring OAuth2 uses HttpSessionOAuth2AuthorizationRequestRepository to save the
   * authorization request. But, since our service is stateless, we can't save it in the session.
   * We'll save the request in a Base64 encoded cookie instead.
   * 
   * All the state related to the authorization request is saved using the
   * authorizationRequestRepository
   */
  @Bean
  public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
    return new HttpCookieOAuth2AuthorizationRequestRepository();
  }

  /**
   * AuthenticationManagerBuilder is used to create an AuthenticationManager instance which is the
   * main Spring Security interface for authenticating a user.
   * 
   * You can use AuthenticationManagerBuilder to build in-memory authentication, LDAP
   * authentication, JDBC authentication, or add your custom authentication provider.
   * 
   * we’ve provided our customUserDetailsService and a passwordEncoder to build the
   * AuthenticationManager.
   * 
   * We’ll use the configured AuthenticationManager to authenticate a user in the login API.
   */
  @Override
  public void configure(AuthenticationManagerBuilder authenticationManagerBuilder)
      throws Exception {
    authenticationManagerBuilder.userDetailsService(customUserDetailsService)
        .passwordEncoder(passwordEncoder());
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }


  @Bean(BeanIds.AUTHENTICATION_MANAGER)
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // @formatter:off
        http
          .cors()
              .and()
          .sessionManagement()
              .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
              .and()
          .csrf()
              .disable()
          .formLogin()
              .disable()
          .httpBasic()
              .disable()
          .exceptionHandling()
              .authenticationEntryPoint(new RestAuthenticationEntryPoint())
              .and()
          .authorizeRequests()
              .antMatchers("/",
                  "/error",
                  "/favicon.ico",
                  "/**/*.png",
                  "/**/*.gif",
                  "/**/*.svg",
                  "/**/*.jpg",
                  "/**/*.html",
                  "/**/*.css",
                  "/**/*.js")
                  .permitAll()
              .antMatchers("/auth/**", "/oauth2/**")
                  .permitAll()
              .anyRequest()
                  .authenticated()
              .and()
          .oauth2Login()
              .authorizationEndpoint()
                  .baseUri("/oauth2/authorize")
                  .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                  .and()
              .redirectionEndpoint()
                  .baseUri("/oauth2/callback/*")
                  .and()
              .userInfoEndpoint()
                  .userService(customOAuth2UserService)
                  .and()
              .successHandler(oAuth2AuthenticationSuccessHandler)
              .failureHandler(oAuth2AuthenticationFailureHandler); 
         // @formatter:on

    // Add our custom Token based authentication filter
    http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
  }
}
