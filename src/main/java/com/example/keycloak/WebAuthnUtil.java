package com.example.keycloak;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.util.Base64UrlUtil;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.WebAuthnPolicy;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class WebAuthnUtil {

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Tạo challenge ngẫu nhiên 32 byte.
     */
    public static byte[] generateChallenge() {
        byte[] challenge = new byte[32];
        secureRandom.nextBytes(challenge);
        return challenge;
    }

    /**
     * Tạo user id ngẫu nhiên 32 byte (dùng cho WebAuthn).
     */
    public static byte[] generateUserId() {
        byte[] userId = new byte[32];
        secureRandom.nextBytes(userId);
        return userId;
    }

    public static String getRpID(KeycloakContext context){
        WebAuthnPolicy policy = getWebAuthnPolicy(context);
        String rpId = policy.getRpId();
        if (rpId == null || rpId.isEmpty()) rpId = context.getUri().getBaseUri().getHost();
        return rpId;
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
