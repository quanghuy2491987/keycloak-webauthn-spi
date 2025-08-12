package com.oddspark.filter;

import com.oddspark.consts.KeycloakConsts;
import com.oddspark.resource.UserPasskeyResource;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import jakarta.ws.rs.Priorities;
import jakarta.annotation.Priority;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;

import java.io.IOException;
import java.util.Set;

@Provider
public class PasskeyCorsFilter implements ContainerRequestFilter, ContainerResponseFilter {

    @Context
    KeycloakSession session;

    private static final Logger logger = Logger.getLogger(PasskeyCorsFilter.class);

    @Override
    public void filter(ContainerRequestContext request) throws IOException {
        String path = request.getUriInfo().getPath();
        logger.info("Received request for path: " + path);

        if (!path.matches(KeycloakConsts.PASSKEY_REGEX)) return;

        logger.info("Processing CORS filter for path: " + path);

        String origin = request.getHeaderString("Origin");
        String clientId = request.getUriInfo().getQueryParameters().getFirst("clientId");

        if (origin == null || clientId == null) return;

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            if (isAllowedOrigin(origin, clientId)) {
                request.abortWith(Response.ok()
                        .header("Access-Control-Allow-Origin", origin)
                        .header("Access-Control-Allow-Credentials", "true")
                        .header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
                        .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
                        .build());
            } else {
                request.abortWith(Response.status(Response.Status.FORBIDDEN)
                        .entity("CORS origin not allowed")
                        .build());
            }
        }
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) throws IOException {
        String path = request.getUriInfo().getPath();
        logger.info("ContainerResponseFilter invoked for path: " + path);

        if (!path.matches(KeycloakConsts.PASSKEY_REGEX)) return;

        logger.info("Processing CORS filter for path: " + path);

        String origin = request.getHeaderString("Origin");
        String clientId = request.getUriInfo().getQueryParameters().getFirst("clientId");

        if (origin != null && clientId != null && isAllowedOrigin(origin, clientId)) {
            response.getHeaders().putSingle("Access-Control-Allow-Origin", origin);
            response.getHeaders().putSingle("Access-Control-Allow-Credentials", "true");
            response.getHeaders().putSingle("Access-Control-Allow-Headers", "origin, content-type, accept, authorization");
            response.getHeaders().putSingle("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
        }
    }

    private boolean isAllowedOrigin(String origin, String clientId) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = session.clients().getClientByClientId(realm, clientId);
        if (client == null) return false;

        Set<String> webOrigins = client.getWebOrigins();
        return webOrigins.contains("*") || webOrigins.contains(String.valueOf(origin));
    }
}
