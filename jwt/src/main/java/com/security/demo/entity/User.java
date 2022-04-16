package com.security.demo.entity;


//some developer don't use user name in class but that is okay so be careful when you use user name class

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.List;
//@Data is like having implicit @Getter, @Setter, @ToString, @EqualsAndHashCode and @RequiredArgsConstructor
//  annotations on the class
//  (except that no constructor will be generated if any explicitly written constructors already exist).
@Entity
//data: pour ne pas ecrire @Column(name="")
@Data
@NoArgsConstructor
@AllArgsConstructor

public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String name;

    //username can be (john 1233) or your name or email that's okay
    private String username;
    private String password;
    //this arraylist mean ont to many or many to many so every user can have many roles but in our case
    //we want

    @ManyToMany(fetch = FetchType.EAGER )
    private List<Role> roles;



}
