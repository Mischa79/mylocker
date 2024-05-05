package com.example.mylocker;


import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class TestController {

    @GetMapping("/secure")
    public String secure(
            Principal principal // пользователь
            // с правами которого выполняется метод
    ) {
        Object user = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        UserDetails details = null;
        if(user instanceof UserDetails)
        {
            details = (UserDetails) user;
        }
        return "secure " + principal.getName() + " " + details.getAuthorities(); // роли
    }

    @GetMapping("/open")
    public String open() {
        return "open";
    }
}
