package com.security.demo.service;

import com.security.demo.entity.Role;
import com.security.demo.entity.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    //username of the user  but username should be unique || roelName name of role
    void addRoleToUser(String username,String roleName);
    //we pass in this case username but the username should be unique
    User getUser(String username);
    List<User> getUsers();
}
