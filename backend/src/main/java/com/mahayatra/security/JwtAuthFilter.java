package com.mahayatra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. Extract the Authorization header
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // 2. Check if the header is missing or doesn't start with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // This allows requests to public endpoints (like /register) to pass through smoothly
            filterChain.doFilter(request, response);
            return;
        }

        // 3. Extract the actual token (remove "Bearer " prefix)
        jwt = authHeader.substring(7);

        try {
            // 4. Extract the email (username) from the token
            userEmail = jwtUtil.extractUsername(jwt);

            // 5. If we have an email and the user is not yet authenticated in this request
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // Fetch the user from the database
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // 6. Validate the token against the database user
                if (jwtUtil.isTokenValid(jwt, userDetails)) {

                    // Create an authentication token
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    // Add details like the user's IP address and session info
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Save the authentication in the Security Context
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            // If the token is expired or malformed, we catch the exception so the app doesn't crash.
            // Spring Security will automatically reject the request and return a 401 Unauthorized.
            System.out.println("JWT Verification failed: " + e.getMessage());
        }

        // 7. Continue the filter chain
        filterChain.doFilter(request, response);
    }
}