package com.tpe.security;

import com.tpe.security.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token=parseToken(request);

        try {
            if (token!=null && jwtUtils.validateToken(token)){

                String username=jwtUtils.getUsernameFromToken(token);
                //login olan userın username
                UserDetails user =userDetailsService.loadUserByUsername(username);
                //login olan securityin userı

                //login olan userı security contexte koymak için authenticaion objesi gerekli
                UsernamePasswordAuthenticationToken authenticated=
                        new UsernamePasswordAuthenticationToken(user,
                                null,//password
                                user.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authenticated);

            }
        }catch (UsernameNotFoundException e){
            e.getStackTrace();
        }

        filterChain.doFilter(request,response);

    }


    //tokenı filtreleyeceğiz, requestden tokenı almamız gerekiyor.
    private String parseToken(HttpServletRequest request){

        String header=request.getHeader("Authorization");//Bearer eyfçdkghfşlghk56
        if (StringUtils.hasText(header) && header.startsWith("Bearer ") ){
            return header.substring(7);
        }
        return null;
    }


}