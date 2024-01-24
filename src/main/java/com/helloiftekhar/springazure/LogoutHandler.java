package com.helloiftekhar.springazure;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
public class LogoutHandler extends SecurityContextLogoutHandler {

    private final ClientRegistrationRepository clientRegistrationRepository;

    public LogoutHandler(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {
        super.logout(request, response, authentication);

        String logoutEndpoint = (String) clientRegistrationRepository
                .findByRegistrationId("azure-dev")
                .getProviderDetails()
                .getConfigurationMetadata()
                .get("end_session_endpoint");


        String logoutUri = UriComponentsBuilder
                .fromHttpUrl(logoutEndpoint+"/?returnTo={returnTo}")
                .encode()
                .toUriString();

        try {
            response.sendRedirect(logoutUri);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
