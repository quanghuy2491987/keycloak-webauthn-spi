package com.oddspark.provider;

import com.oddspark.resource.UserPasskeyResource;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class UserPasskeyProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public UserPasskeyProvider(KeycloakSession session ) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new UserPasskeyResource(session);
    }

    @Override
    public void close() {
    }
}
