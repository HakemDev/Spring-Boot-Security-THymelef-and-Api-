package com.security.demo.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.demo.dto.RoleToUserForm;
import com.security.demo.entity.Role;
import com.security.demo.entity.User;
import com.security.demo.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
@Slf4j
public class UserResource {
    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>>getUsers(){
        return ResponseEntity.ok().body(userService.getUsers());
    }
    @PostMapping("/user/save")
    public ResponseEntity<User>saveUser(@RequestBody User user)
    {
        //in create methode we will write the server path
        URI uri =URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        //return ResponseEntity.ok().body(userService.saveRole(role));
        //we replace ok with created we use that when we want save something
        //created method should have an uri that posting to
        // instead of write 200 that's mean ok  it's more precise to send a 201
        //which mean something was created on the server resource was created on the server
        //using 200 is fine but it's better to be more precise
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role>saveRole(@RequestBody Role role)
    {
        URI uri =URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("role/addtouser")
    public ResponseEntity<String>addRoleToUser(@RequestBody RoleToUserForm form)
    {
        userService.addRoleToUser(form.getUsername(),form.getRoleName());
        return ResponseEntity.ok().build();
    }
    //16 we will send http:localhost:8080/api/refreshtoken to send access token again
    @GetMapping("/token/refresh")
    public void refreshtoken(HttpServletRequest request, HttpServletResponse response) throws IOException {
            String authorizationHeader=request.getHeader(AUTHORIZATION);
            //check if there is header and check that the header start with beat
            if(authorizationHeader!=null && authorizationHeader.startsWith("Bearer "))
            {
                //whnenever we need to from the front end, sending a request to the backend, we are going to send the
                // token after we have authenticated successfully.so we log in, you are successful
                // we get the token, we are going to send another request with that token
                // so whenever we send the request with the token, we are going to put the word bear and in the space,
                // and and then the token. and that simply  mean that whoever is sending the request passing in this token
                //once we verify that the token is valid, you don't have to do anything.
                // give this person all the permission and everything that comes with their token.there's no further
                // validation that is needed, because they are like the bearers of the token, like it's their own token
                // so then if this is the case, then we are going to start putting in the logic that we need to put in.
                try{
                    String refresh_token =authorizationHeader.substring("Bearer ".length());
                    Algorithm algorithm=Algorithm.HMAC256("secret".getBytes());
                    JWTVerifier verifier= JWT.require(algorithm).build();
                    DecodedJWT decodedJWT=verifier.verify(refresh_token);
                    String username = decodedJWT.getSubject();
                    /*16
                        will get user form our database to make sure that this user actually exists
                     */
                    User user=userService.getUser(username);
                    //16 send another token to user
                    String access_token= JWT.create()
                            .withSubject(user.getUsername())//passing username unique!!!
                            .withExpiresAt(new Date(System.currentTimeMillis()+10*60*1000))//10:minutes, 60:seconds, 1000:millisecond
                            .withIssuer(request.getRequestURI().toString())
                            .withClaim("roles",user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                            .sign(algorithm);
                    Map<String,String> tokrns=new HashMap<>();
                    Map<String,String> tokens=new HashMap<>();
                    tokens.put("access_token",access_token);
                    tokens.put("refresh_token",refresh_token);
                    response.setContentType(APPLICATION_JSON_VALUE);
                    /*11
                        return everything in the body and a nice json format
*/
                    new ObjectMapper().writeValue(response.getOutputStream(),tokens);
                }catch(Exception exception){
                    log.error("Error logging in:{}",exception.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    response.setHeader("error",exception.getMessage());
                    Map<String,String> error=new HashMap<>();
                    error.put("error_message2",exception.getMessage());
                    response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
                    // getOutputStream--->add methode to signature
                    new ObjectMapper().writeValue(response.getOutputStream(),error);
                }

            }else{
                        throw new RuntimeException("Refresh token is missing");
              }

        }

}
