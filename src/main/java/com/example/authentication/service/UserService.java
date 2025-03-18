// package com.example.authentication.service;

// import com.example.authentication.dto.AuthResponse;
// import com.example.authentication.dto.LoginRequest;
// import com.example.authentication.dto.RegisterRequest;
// import com.example.authentication.model.Role;
// import com.example.authentication.model.User;
// import com.example.authentication.repository.UserRepository;

// import java.util.HashMap;
// import java.util.Map;

// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.stereotype.Service;

// @Service
// public class UserService {

//     private final UserRepository userRepository;
//     private final PasswordEncoder passwordEncoder;
//     private final JwtService jwtService;

//     public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
//         this.userRepository = userRepository;
//         this.passwordEncoder = passwordEncoder;
//         this.jwtService = jwtService;
//     }

//     public String register(RegisterRequest request) {
//         // Check if a user with the given email already exists
//         if (userRepository.findByEmail(request.getEmail()).isPresent()) {
//             Map<String, String> response = new HashMap<>();
//             response.put("message", "Email is already in use");
//             return "Email is already in use";
//         }

//         User user = User.builder()
//                 .username(request.getUsername())
//                 .email(request.getEmail())
//                 .password(passwordEncoder.encode(request.getPassword()))
//                 .role(Role.USER)
//                 .build();

//         userRepository.save(user);
//         return "User registered successfully!";
//     }

//     public AuthResponse login(LoginRequest request) {
//         User user = userRepository.findByEmail(request.getEmail())
//                 .orElseThrow(() -> new RuntimeException("Invalid credentials"));

//         if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
//             throw new RuntimeException("Invalid credentials");
//         }

//         String token = jwtService.generateToken(user.getEmail());
//         return new AuthResponse(token);
//     }
// }


// package com.example.authentication.service;

// import com.example.authentication.dto.AuthResponse;
// import com.example.authentication.dto.LoginRequest;
// import com.example.authentication.dto.RegisterRequest;
// import com.example.authentication.model.Role;
// import com.example.authentication.model.User;
// import com.example.authentication.repository.UserRepository;

// import java.util.HashMap;
// import java.util.Map;

// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.stereotype.Service;

// @Service
// public class UserService {

//     private final UserRepository userRepository;
//     private final PasswordEncoder passwordEncoder;
//     private final JwtService jwtService;

//     public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
//         this.userRepository = userRepository;
//         this.passwordEncoder = passwordEncoder;
//         this.jwtService = jwtService;
//     }

//     public Map<String, String> register(RegisterRequest request) {
//         Map<String, String> response = new HashMap<>();

//         // Check if user exists
//         if (userRepository.findByEmail(request.getEmail()).isPresent()) {
//             response.put("message", "Email is already in use");
//             return response;
//         }

//         // Create new user
//         User user = User.builder()
//                 .username(request.getUsername())
//                 .email(request.getEmail())
//                 .password(passwordEncoder.encode(request.getPassword()))
//                 .role(Role.USER)
//                 .build();

//         userRepository.save(user);
//         response.put("message", "User registered successfully!");
//         return response;
//     }

//     public AuthResponse login(LoginRequest request) {
//         User user = userRepository.findByEmail(request.getEmail())
//                 .orElseThrow(() -> new RuntimeException("Invalid credentials"));

//         if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
//             throw new RuntimeException("Invalid credentials");
//         }

//         String token = jwtService.generateToken(user.getEmail());
//         return new AuthResponse(token);
//     }
// }



package com.example.authentication.service;

import com.example.authentication.dto.AuthResponse;
import com.example.authentication.dto.LoginRequest;
import com.example.authentication.dto.RegisterRequest;
import com.example.authentication.model.Role;
import com.example.authentication.model.User;
import com.example.authentication.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public ResponseEntity<Map<String, String>> register(RegisterRequest request) {
        Optional<User> existingUser = userRepository.findByEmail(request.getEmail());
        Map<String, String> response = new HashMap<>();

        if (existingUser.isPresent()) {
            response.put("message", "Email is already in use");
            return ResponseEntity.badRequest().body(response);
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);
        response.put("message", "User registered successfully!");
        return ResponseEntity.ok(response);
    }

    public ResponseEntity<?> login(LoginRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());

        if (userOptional.isEmpty()) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials"));
        }

        User user = userOptional.get();
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials"));
        }

        String token = jwtService.generateToken(user.getEmail());
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
