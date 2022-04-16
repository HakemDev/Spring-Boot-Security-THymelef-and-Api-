package com.security.demo.service;

import com.security.demo.entity.Role;
import com.security.demo.entity.User;
import com.security.demo.repository.RoleRepo;
import com.security.demo.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
//that annotation is for loging ||allowing the end user to plug in the desired logging framework at deployment time.
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {
    //for those two variables we should add a constructor for both of them to add them to the class
    //but there is an easy way is add an annotation call RequiredArgsConstructor intoduced by lombak
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;
    //3-add a new bean for userDetailService
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user=userRepo.findByUsername(username);
        if(user==null){
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User Not found in the database");
        }
        else{
            log.info("User found in the database: {}",username);
        }
        Collection<SimpleGrantedAuthority> authorities=new ArrayList<>();
        user.getRoles().forEach(role->{
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        //we have return spring security user that is expecting to be returned so that
        //it can take this information and then do the password comparaison
        // and check all the authority and everything
        return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPassword(),authorities);
    }

    @Override
    public User saveUser(User user) {
        log.info("saving new user {} to db",user.getName());
        /*9
            we are saving the raw passwords because we are using the password encoder,
            so we have to encode(make it crypted) the user password and then save the user in the database
         */
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new role {} to db",role.getName());
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("adding role {} to user {} ",roleName,username);
        User user=userRepo.findByUsername(username);
        Role role=roleRepo.findByName(roleName);
        user.getRoles().add(role);

    }

    @Override
    public User getUser(String username) {
        log.info("fetching user {} ",username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("fetching all users");
        return userRepo.findAll();
    }

}
