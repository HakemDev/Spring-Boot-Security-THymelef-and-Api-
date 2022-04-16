package com.security.demo.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    /*14
        OncePerRequestFilter: will intercept every request that comes into the application
        doFilterInternal: so all the logic we are going to put to filter the request coming in and determine if the user has
        access to the application or not
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        /*14
            The first thing i want to do is to check to see if this is not the login path, because if this is the case,
             then i don't want try to do anything here.I just want to let it go through.
         */
        //18 add new url  /api/token/refresh/
        if(request.getServletPath().equals("/login") || request.getServletPath().equals("/api/token/refresh")){
            /*14
                this line just gonna to make this filter pass the request to the next filter and the f/token/refresher chain
                which mean we are not doing anything. if it's API for /login then we don't do anything.let the request
                go through(mean we will not do anything we just let it pass).
             */
            filterChain.doFilter(request,response);
        }//14 in else we need to start checking to see if this has an authorization and then see the user as the logged
        else{
            System.out.println("path is "+request.getServletPath());
            String authorizationHeader=request.getHeader(AUTHORIZATION);
            //check if there is  an authorization header and check that the header start with Bearer
            if(authorizationHeader!=null && authorizationHeader.startsWith("Bearer "))
            {/*14
                 whenever we need to from the front end, sending a request to the backend, we are going to send the
                 token after we have authenticated successfully.so we log in, you are successful
                 we get the token, we are going to send another request with that token
                 so whenever we send the request with the token, we are going to put the word bear and the space,
                 and then the token path. and that simply  mean that whoever is sending the request passing in this token
                 once we verify that the token is valid, you don't have to do anything.
                 give this person all the permission and everything that comes with their token.there's no further
                 validation that is needed, because they are like the bearers of the token, like it's their own token
                 so then if this is the case, then we are going to start putting in the logic that we need to put in.
                */
                try{
                    //14 here we just remove Bearer+space because we only need the token and we can do that by calling this substring
                    // and then passing how many letters we want to remove
                    String token =authorizationHeader.substring("Bearer ".length());
                    //14 the same as we write in SecurityConfig file
                    Algorithm algorithm=Algorithm.HMAC256("secret".getBytes());
                    //14 create the verifier
                    JWTVerifier verifier= JWT.require(algorithm).build();
                    //14 verify the token
                    DecodedJWT decodedJWT=verifier.verify(token);
                    //14 when we verify the token is valid we grab the username of the user
                    String username = decodedJWT.getSubject();
                    /*14
                         roles is a key that we write previously in CustomAuthenticationFilter at line 98
                         it's going to look at the json web token look at the roles and then grab all of the
                         collection that is there.
                         asArray determine how we want to collect it.
                         jusqu'a maintenant on a déterminer username, roles mais on a pas besoin de password
                         parceque l'utilisateur est déja authentifié et json web token ou acces token is valid
                         we just need to set them in the authentication context

                     */
                    String[] roles=decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<SimpleGrantedAuthority> authorities=new ArrayList<>();
                    stream(roles).forEach(role->{
                        /*14 those are the roles that we will work with  because the reason why we have to do
                         this conversion, it's actually beacause we need to get those roles and convert them
                         into something that extends GRAND AUTHORITY SIMPLE
                         AND THAT WHAT SPRING SECURITY EXPECTING AS THE ROLES OF THE USER
                         we ca,'t pass those rules as an array of strength.
                        */
                        authorities.add(new SimpleGrantedAuthority((role)));
                    });
                    UsernamePasswordAuthenticationToken authenticationToken=
                            new UsernamePasswordAuthenticationToken(username,null,authorities);
                    /*14
                        that's how we tell spring security hey this is the username and their roles
                        and this is what they can do in the application.
                        so spring is going to look at the user, look at their role, and determine what resource
                        they can acces  and what they can't acces depending on the roles
                     */
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    /*14
                    and then after we do all that, we are going to go ahead and call the filter chain
                    to let the request continued here way
                     */
                    filterChain.doFilter(request,response);

                }catch(Exception exception){
                     /*14
                         here we handle exception: let's say the the token wasn't valid or weren't able to verify it
                         or expires..., so we need to send something back to the user so that they know what happens
                      */
                    log.error("Error logging in:{}",exception.getMessage());
                    //14 passing some header
                    response.setHeader("error",exception.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    Map<String,String> error=new HashMap<>();
                    error.put("error_message3",exception.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(),error);

                }

            }else{
                //14 let request continue
                filterChain.doFilter(request,response);
            }

        }
    }
}
