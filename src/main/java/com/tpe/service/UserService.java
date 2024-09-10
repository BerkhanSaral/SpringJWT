package com.tpe.service;



import com.tpe.domain.Role;
import com.tpe.domain.User;
import com.tpe.domain.enums.RoleType;
import com.tpe.dto.RegisterUser;
import com.tpe.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final RoleService roleService;

    private final PasswordEncoder passwordEncoder;


    public void saveUser(RegisterUser registerUser) {

        Role role =roleService.getRoleByType(RoleType.ROLE_STUDENT);
        Set<Role> roleSet=new HashSet<>();
        roleSet.add(role);

        User user=new User();
        user.setFirstName(registerUser.getFirstName());
        user.setUserName(registerUser.getUserName());
        user.setPassword(passwordEncoder.encode(registerUser.getPassword()));
        user.setRoles(roleSet);

        userRepository.save(user);

    }
}