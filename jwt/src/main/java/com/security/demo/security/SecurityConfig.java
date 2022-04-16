package com.security.demo.security;

import com.security.demo.filter.CustomAuthenticationFilter;
import com.security.demo.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
//WebSecurityConfiguration  a class that contains methode manage the users and the security and the application
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //2-add attribut
    // we don't have any configuration or any ovveride for this two beans
    //so we need to create two beans in our application
    // to tell spring how we want to upload the user and then create a bean for  the password
    // we can create our own password encoder but we can just use the one from spring
    private final UserDetailsService usetdeatil;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
//2-add that methode
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //there is many method to tell spring how to look for the users that can connect like userDetailService
        // Jpa is already doing a lot of work for us
        // userDetailsService is going to accept a user detail service
        //,which is a beam that we have to override until
        // until spring how to go look for the users
        auth.userDetailsService(usetdeatil).passwordEncoder(bCryptPasswordEncoder);
    }
    //2-add that methode
    //4
    // earlier when we were trying to access the applciation where we had to provide the username user
    // and the password that was genearted by spring
    //spring is using a session policy that was stateful.so he was using session
    //and then save something in memory  tracking the user by giving
    // them a cookie.but we don't want to use this system we want use a json web token system or a token
    // system where the user logs in. we give the a token and we don't keep track of the user
    //whith no cookies or anything like that by using httpSecurity
    @Override
    protected void configure(HttpSecurity http) throws Exception {

       /* Change url from /login to /api/login
       CustomAuthenticationFilter customAuthenticationFilter=new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");*/
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //17 add new url that we be permit it
        http.authorizeRequests().antMatchers("/login/**","/api/token/refresh/**").permitAll();//12 if we want to allow certain path to access for everyone we will add this line of code but you should put that line in order for tne next line code
        http.authorizeRequests().antMatchers(GET,"/api/user/**").hasAnyAuthority("ROLE_USER");//12 without that line since now we almost didn't even have any security   //allow everyone to be able to access this applisation at this point because i have permitall with the code exist in the next line, in this line we want to say anything come from /api/user/** should have user role
        http.authorizeRequests().antMatchers(POST,"/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");
        http.authorizeRequests().anyRequest().authenticated();//.permitAll();//12 wave to remove permitall() because that means that we just throw our security out of the window so we delete permitall() and add authenticated()
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
        //we gonna have an authentification filter so that we can check the user
        // whenever they are trying to log in
        //7-add custom authentification filter
        http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));

        /*15
         add filter exist in customauthorizationfilter file of verify authorization and we should
         be sure that filter is coming before other filters by using addFilterBefore, because we need to intercept every request before
         before any other filters.
         */
        http.addFilterBefore(new CustomAuthorizationFilter(),UsernamePasswordAuthenticationFilter.class);
    }
    //7- we want the authentication manager to use it on the filter
    //after we add authenticationManagerBean to filter we have to give the user the token or their access
    // token or refresh token whenever the login successfully
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception{
        return super.authenticationManagerBean();
    }
}
