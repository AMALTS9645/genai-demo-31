 //code-start
import org.springframework.http.ResponseEntity
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.http.HttpResponseEntity
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.http.HttpEntity
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus.BAD_REQUEST
import org.springframework.http.HttpStatus.UNAUTHORIZED
import org.springframework.http.HttpMethod.GET
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.http.HttpStatus.NOT_FOUND
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.validation.annotation.Validated
import org.springframework.security.security.config.annotation.WebSecurityConfigurerAdapter
import org.springframework.security.config.annotation.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.configure(WebSecurityConfigurerAdapter.Builder)
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.embedded.DefaultPasswordEncoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.configure(HttpSecurity)
import org.springframework.security.config.annotation.authentication.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.configuration.configure(AuthenticationManagerBuilder)
import org.springframework.security.config.annotation.web.configuration.configure(HttpSecurity)
import org.springframework.security.config.annotation.web.configuration.configure(HttpSecurity)

import org.springframework.security.config.annotation.web.configuration.formAuthentication
import org.springframework.security.config.annotation.web.configuration.formAuthentication
import org.springframework.security.config.annotation.web.configuration.configure(HttpSecurity)
import org.springframework.security.config.annotation.web.configuration.formLogin
import org.springframework.security.config.annotation.web.configuration.formLogin
import org.springframework.security.config.annotation.web.configuration.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.annotation.global.GlobalMethodSecurity

import org.springframework.security.config.annotation.authentication.AuthenticationSuccessHandler
import org.springframework.security.config.annotation.web.configuration.HttpSecurity
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.web.authentication.UserDetailsService
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationToken

import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsServiceImpl
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestParam;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.GlobalAuthenticationEntryPoint;
import org.springframework.security.config.annotation.web.configuration.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.formLogin;
import org.springframework.security.config.annotation.web.configuration.formLogin;
import org.springframework.security.config.annotation.web.configuration.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.SecurityFilterChain;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import org.springframework.security.web.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.AuthenticationProvider;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UserDetailsServiceImpl;
import org.springframework.security.web.authentication.UserDetails;
import org.springframework.security.web.authentication.UserDetailsService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class LoginController {

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        if (username == null || password == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username and password are required");
        }

        // UserDetailsServiceImpl is a simple UserDetailsService implementation for this example
        UserDetails user = new UserDetailsServiceImpl().loadUserByUsername(username);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }

        String passwordEncoded = user.getPassword();
        String passwordEncodedInput = password;

        return ResponseEntity.ok().body(Unauthorized);
    }
}

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .passwordEncoder(new BCryptPasswordEncoder())
            .passwordAuthentication(auth -> {
                return new UsernamePasswordAuthenticationToken(
                        auth.getUserDetailsService().loadUserByUsername(auth.getUsername()),
                        auth.getPasswordEncoder().encode(passwordInput),
                        new ArrayList<>());
            });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated()
            .and()
            .formLogin().loginPage("/login").permitAll()
            .and()
            .exceptionHandling().accessDeniedHandler(accessDeniedHandler());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService());
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    @Bean
    public SecurityFilterChain securityFilterChain() throws Exception {
        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        AuthenticationSuccessHandler successHandler = new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                    Authentication authentication) throws IOException, ServletException {
                response.setStatus(HttpStatus.OK.value());
                response.getWriter().write("Login successful");
            }
        };
    }

    private AuthenticationManager authenticationManager() throws Exception {
        return new DefaultPasswordEncoder().setPasswordEncoder(new BCryptPasswordEncoder());
    }

    @Bean
    public GlobalAuthenticationEntryPoint accessDeniedHandler() {
        return new GlobalAuthenticationEntryPoint() {
            @Override
            public void commence(HttpServletRequest request, HttpServletResponse response,
                    AuthenticationException authException) throws IOException, ServletException {
                response.sendError(HttpStatus.NOT_FOUND.value());
            }
        };
    }
}

class UserDetailsServiceImpl implements UserDetailsService {

    private static Map<String, UserDetails> users = new HashMap<>();

    public UserDetails loadUserByUsername(String username) {
        UserDetails user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        return user;
    }

    @Override
    public boolean loadUserByUsername(String username) throws UsernameNotFoundException {
        return users.containsKey(username);
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities(String username) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean loadUserByAuthorities(Collection<? extends GrantedAuthority> authorities) {
        throw new UnsupportedOperationException();
    }

    public void setUser(String username, String password) {
        users.put(username, new UserDetailsImpl(username, password));
    }

    private class UserDetailsImpl implements UserDetails {
        private String username;
        private String password;

        public UserDetailsImpl(String username, String password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}