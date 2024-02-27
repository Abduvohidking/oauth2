package uz.rsa.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/welcome")
public class hello {
    @GetMapping("/hello")
    public String hello(){
        return "Hello World";
    }
}
