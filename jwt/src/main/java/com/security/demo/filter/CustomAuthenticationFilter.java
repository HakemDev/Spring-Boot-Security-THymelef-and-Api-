package com.security.demo.filter;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
//6/

//6 Slf4j read log
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
    //6 attemptAuthentication: whenever the user tries to log this method will play
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username=request.getParameter("username");
        String password=request.getParameter("password");
        log.info("username is {}",username);
        log.info("Password is:{}",password);
        UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(username,password);
        //6 here we tel  authenticationManager to authenticate the user that is logging in here with this request
        return authenticationManager.authenticate(authenticationToken);
    }

    /*6
         successfulAuthentication: this methode will work if login is successful
         we use this method t be ables to send the access token and refresh token whenever login is
         successful
     */

    /*8
        for this method we want to give the user their access token and the refresh token after they
         have successfully logged inf, because this method is called once the login is successful, which
         means that we need to have some sort of way to generate the token, sign the token, and then send the
        token over the user. and we can do this all by ourselves.but that's a lot of work and we probably don't
         want to do that outsell, so we can use some external library to do that for us. so i'm going
         google.com->Search 'auth0.java jwt maven'--->clicker sur un lien in this case we choose 'MVNREPOSITORY' Web site
         --->copier maven dependency of jwt <dependency>                             and then past it in pom.xml
                                                  <groupId>com.auth0</groupId>
                                                  <artifactId>java-jwt</artifactId>
                                                  <version>3.19.1</version>
                                            </dependency>
    */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        /*8
             to get user successfuly logged in we can define a user coming from spring security
             (org.springframework.security.core.details)
             getPrincipal returning an object is the user that's been successfully authenticated
         */
        User user=(User)authentication.getPrincipal();

        /*8
             Now we have access to this user. so we can get information from that logged in user to create JWT.
             we will use auth0 library tht we have add to pom.xml to call method algorithm that i'm going to use to
             sign the JWT and the refresh token.
         */

        Algorithm algorithm=Algorithm.HMAC256("secret".getBytes());
        /*8
            Create a token  name access_token.
            withSubject: contain something unique to user that authentified in our case username is unique.
            withExpiresAt: specify the time for a token to leave.
            System.currentTimeMillis(): current system time.
            withIssuer: to specify the author of this token.
            withClaim: gonna be all the claims of the user.so whatever permissions or authorities or roles
                       that we put in for that specific user we are gonna pass those into the token as the rules
                       of that specific user
         */
        String access_token= JWT.create()
                .withSubject(user.getUsername())//passing username unique!!!
                .withExpiresAt(new Date(System.currentTimeMillis()+10*60*1000))//10:minutes, 60:seconds, 1000:millisecond
                .withIssuer(request.getRequestURI().toString())
                .withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);
        /*8
          Create a refresh toke name refresh_token
         */

        String refresh_token= JWT.create()
                .withSubject(user.getUsername())//passing username unique!!!
                .withExpiresAt(new Date(System.currentTimeMillis()+30*60*1000))//10:minutes, 60:seconds, 1000:millisecond
                .withIssuer(request.getRequestURI().toString())
                .sign(algorithm);
        /*8
            we can use the response to send those tokens to the user in the front end.
            so whenever he user logs in successfully, we can check the headers in the
            response, they should have the access token and refresh token
         */
        /*11
        comment those response
        */
        /*
        response.setHeader("access_token",access_token);
        response.setHeader("refresh_token",refresh_token);
        */
        /*11
            you can use the Object mapper to pass in json.
            so instead of setting headers , i want to actually send
            something in the response body
            so we will say a nice json format in result
         */
        Map<String,String> tokens=new HashMap<>();
        tokens.put("access_token",access_token);
        tokens.put("refresh_token",refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        /*11
            return everything in the body and a nice json format
         */
        new ObjectMapper().writeValue(response.getOutputStream(),tokens);
    }
}
