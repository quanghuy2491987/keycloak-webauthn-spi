package com.oddspark.provider.factory;

import com.oddspark.consts.KeycloakConsts;
import com.oddspark.resource.UserPasskeyResource;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class UserPasskeyProviderFactory implements RealmResourceProviderFactory {

    @Override
    public String getId() {
        return KeycloakConsts.PASSKEY_ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new RealmResourceProvider() {
            @Override
            public Object getResource() {
                return new UserPasskeyResource(session);
            }

            @Override
            public void close() {}
        };
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
