package com.security.demo.repository;

import com.security.demo.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role,Integer> {
   //name: is the name of the role
    Role findByName(String name);
}
