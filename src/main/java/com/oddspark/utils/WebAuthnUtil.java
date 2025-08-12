package com.oddspark.utils;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import org.apache.http.HttpHeaders;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class WebAuthnUtil {

    private static final org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(WebAuthnUtil.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Create 32 byte random challenge.
     */
    public static byte[] generateChallenge() {
        byte[] challenge = new byte[32];
        secureRandom.nextBytes(challenge);
        return challenge;
    }

    public static String getRpID(KeycloakContext context){
        WebAuthnPolicy policy = getWebAuthnPolicy(context);
        String rpId = policy.getRpId();
        if (rpId == null || rpId.isEmpty()) rpId = context.getUri().getBaseUri().getHost();
        return rpId;
    }

    /**
     * Extract Bearer token from HttpRequest
     * @param request {@link HttpRequest}
     * @return
     */
    public static String extractBearerToken(HttpRequest request) {
        String authHeader = request.getHttpHeaders().getHeaderString(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring("Bearer ".length());
        }
        return null;
    }

    /**
     * Get user session from user login
     * @param session keycloak session
     * @return user session
     */
    public static UserSessionModel authorizerUserSession(KeycloakSession session){

        RealmModel realm = session.getContext().getRealm();
        UserSessionModel userSession = null;

        // Try check with cookie
        logger.info("Checking user session with identity cookie");
        AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
        if (authResult != null) {
            userSession = authResult.getSession();
        }

        // 2. If done have in cookie, check with Bearer Token
        if (userSession == null) {

            AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session)
                    .authenticate();
            logger.info("Checking user session with access token");
            if (auth != null) {
                AccessToken accessToken = auth.getToken();
                String sessionId = accessToken.getSessionId();
                userSession = session.sessions().getUserSession(realm, sessionId);
            }
        }
        return userSession;
    }

    public static Origin getOrigin(KeycloakContext context){
        String originStr = context.getUri().getBaseUri().toString();
        Origin origin = new Origin(originStr);
        return origin;
    }

    public static WebAuthnPolicy getWebAuthnPolicy(KeycloakContext context) {
        return context.getRealm().getWebAuthnPolicy();
    }

    public static List<Long> convertSignatureAlgorithms(List<String> signatureAlgorithmsList) {
        List<Long> algs = new ArrayList();
        if (signatureAlgorithmsList == null || signatureAlgorithmsList.isEmpty()) return algs;

        for (String s : signatureAlgorithmsList) {
            switch (s) {
                case Algorithm.ES256 :
                    algs.add(COSEAlgorithmIdentifier.ES256.getValue());
                    break;
                case Algorithm.RS256 :
                    algs.add(COSEAlgorithmIdentifier.RS256.getValue());
                    break;
                case Algorithm.ES384 :
                    algs.add(COSEAlgorithmIdentifier.ES384.getValue());
                    break;
                case Algorithm.RS384 :
                    algs.add(COSEAlgorithmIdentifier.RS384.getValue());
                    break;
                case Algorithm.ES512 :
                    algs.add(COSEAlgorithmIdentifier.ES512.getValue());
                    break;
                case Algorithm.RS512 :
                    algs.add(COSEAlgorithmIdentifier.RS512.getValue());
                    break;
                case Algorithm.Ed25519:
                    algs.add(COSEAlgorithmIdentifier.EdDSA.getValue());
                    break;
                case "RS1" :
                    algs.add(COSEAlgorithmIdentifier.RS1.getValue());
                    break;
                default:
                    // NOP
            }
        }

        return algs;
    }
}

