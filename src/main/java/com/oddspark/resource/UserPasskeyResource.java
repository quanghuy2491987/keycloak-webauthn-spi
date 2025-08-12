package com.oddspark.resource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oddspark.consts.KeycloakConsts;
import com.oddspark.request.PasskeyRequest;
import com.oddspark.utils.WebAuthnUtil;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.attestation.statement.androidkey.AndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.TPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.WebAuthnConstants;
import org.keycloak.credential.*;
import org.keycloak.models.*;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.util.*;

@Path(KeycloakConsts.PASSKEY_ROOT_PATH)
public class UserPasskeyResource {

    private static final Logger logger = Logger.getLogger(UserPasskeyResource.class);
    private final KeycloakSession session;
    private final CertPathTrustworthinessValidator certPathTrustValidator;

    @Inject
    public UserPasskeyResource(KeycloakSession session) {
        this.session = session;
        this.certPathTrustValidator = new NullCertPathTrustworthinessValidator();
    }

    @GET
    @Path(KeycloakConsts.PASSKEY_GET_CHALLENGE_PATH)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChallenge() {
        logger.info("--------------Generating WebAuthn Challenge--------------");

        logger.info("Validation realm");
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) return missingRealmResponse();

        logger.info("Validation authentication");
        UserSessionModel userSession = WebAuthnUtil.authorizerUserSession(session);

        if (Objects.isNull(userSession)) {
            return userUnauthorized();
        }

        logger.info("Generate challenge");
        WebAuthnPolicy policy = WebAuthnUtil.getWebAuthnPolicy(session.getContext());
        List<String> signatureAlgorithmsList = policy.getSignatureAlgorithm();
        // Convert human-readable algorithms to their COSE identifier form
        List<Long> signatureAlgorithms = WebAuthnUtil.convertSignatureAlgorithms(signatureAlgorithmsList);

        // Generate a new challenge
        String challengeBase64 = Base64UrlUtil.encodeToString(WebAuthnUtil.generateChallenge());
        String rpId = WebAuthnUtil.getRpID(session.getContext());
        String userName = userSession.getUser().getUsername();
        String userId = userSession.getUser().getId();

        //save challenge to user session
        long ttl = KeycloakConsts.CHALLENGE_TTL_MINUTE * 60 * 1000;
        long expireAt = LocalDateTime.now().getNano() + ttl;

        userSession.setNote(KeycloakConsts.CHALLENGE_KEY, challengeBase64);
        userSession.setNote(KeycloakConsts.CHALLENGE_EXPIRY_KEY, String.valueOf(expireAt));

        Map response = Map.of(WebAuthnConstants.CHALLENGE, challengeBase64,
                WebAuthnConstants.USER_ID, userId,
                WebAuthnConstants.USER_NAME, userName,
                WebAuthnConstants.SIGNATURE_ALGORITHMS, signatureAlgorithms,
                WebAuthnConstants.RP_ID, rpId);

        logger.info("--------------Generating WebAuthn Challenge completed--------------");

        // Return the challenge as JSON response
        return Response.ok(response)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .build();
    }

    @POST
    @Path(KeycloakConsts.PASSKEY_REGISTER_PATH)
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response savePasskey(PasskeyRequest request) throws JsonProcessingException, UnsupportedEncodingException {

        logger.info("--------------Register passkey--------------");

        logger.info("Validation realm");
        // Get the current realm
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) return missingRealmResponse();

        logger.info("Validation authentiation");
        UserSessionModel userSession = WebAuthnUtil.authorizerUserSession(session);
        if (Objects.isNull(userSession)) {
            return userUnauthorized();
        }
        UserModel userModel = userSession.getUser();

        logger.info("Validation credential");
        String base64ClientDataJSON = request.getClientDataJSON();

        byte[] base64ClientDataJSONBytes = Base64.getDecoder().decode(base64ClientDataJSON);
        String decodedClientDataJSON = new String(base64ClientDataJSONBytes, Charsets.UTF_8.name());

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode clientData = objectMapper.readTree(decodedClientDataJSON);

        Origin origin = new Origin(clientData.get(WebAuthnConstants.ORIGIN).asText());
        String rpId = clientData.get(WebAuthnConstants.ORIGIN).asText().replace("http://", "").replace("https://", "").split(":")[0];

        String challengeStr = userSession.getNote(KeycloakConsts.CHALLENGE_KEY);
        String expiryStr = userSession.getNote(KeycloakConsts.CHALLENGE_EXPIRY_KEY);
        String requestChallenge = Objects.nonNull(clientData.get(WebAuthnConstants.CHALLENGE)) ? clientData.get(WebAuthnConstants.CHALLENGE).asText() : null;

        if (Objects.isNull(challengeStr) || Objects.isNull(expiryStr)
                || Long.parseLong(expiryStr) < LocalDateTime.now().getNano()
                || !StringUtils.equals(challengeStr, requestChallenge)) {
            userSession.removeNote(KeycloakConsts.CHALLENGE_KEY);
            userSession.removeNote(KeycloakConsts.CHALLENGE_EXPIRY_KEY);
            return challengeExpired();
        }

        Challenge challenge = new DefaultChallenge(requestChallenge);

        Set<Origin> originSet = new HashSet<>();
        originSet.add(origin);
        ServerProperty serverProperty = new ServerProperty(originSet, rpId, challenge, null);
        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, true);

        byte[] attestationObject = Base64.getDecoder().decode(request.getAttestationObject());

        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, base64ClientDataJSONBytes);

        // Parse and validate registration data
        WebAuthnRegistrationManager webAuthnRegistrationManager = createWebAuthnRegistrationManager();
        RegistrationData registrationData = webAuthnRegistrationManager.parse(registrationRequest);
        webAuthnRegistrationManager.validate(registrationData, registrationParameters);

        WebAuthnCredentialModelInput credential = new WebAuthnCredentialModelInput(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
        credential.setAttestedCredentialData(registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData());
        credential.setCount(registrationData.getAttestationObject().getAuthenticatorData().getSignCount());
        credential.setAttestationStatementFormat(registrationData.getAttestationObject().getFormat());
        credential.setTransports(registrationData.getTransports());

        WebAuthnCredentialProvider webAuthnCredProvider = (WebAuthnCredentialProvider) this.session.getProvider(CredentialProvider.class, WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID);
        WebAuthnCredentialModel credentialModel = webAuthnCredProvider.getCredentialModelFromCredentialInput(credential, userModel.getUsername());

        WebAuthnCredentialModel webAuthnCredentialModel = WebAuthnCredentialModel.createFromCredentialModel(credentialModel);

        userModel.credentialManager().createStoredCredential(webAuthnCredentialModel);

        logger.info("--------------Register passkey completed--------------");

        Map responsea = Map.of("success", true, "message", "Passkey stored successfully");
        return Response.status(Response.Status.CREATED)
                .entity(responsea)
                .build();
    }

    @GET
    @Path(KeycloakConsts.PASSKEY_GET_CHALLENGE_AUTHENTICATION_PATH)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCredentialId(@QueryParam("clientId") String clientId, @QueryParam("userName") String userName, @Context UriInfo uriInfo) {

        logger.info("--------------Generate challenge authentication--------------");

        logger.info("Validation realm");
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) return missingRealmResponse();

        UserModel user = session.users().getUserByUsername(realm, userName);
        ClientModel client = realm.getClientByClientId(clientId);

        logger.info("Validation client");
        if (client == null) {
            return buildErrorResponse(Response.Status.BAD_REQUEST, "Missing client context");
        }

        logger.info("Validation user");
        if (user == null) {
            return buildErrorResponse(Response.Status.NOT_FOUND, "User not found");
        }

        logger.info("Validation passkey registed");
        // Get all WebAuthn credentials for the user
        List<CredentialModel> webAuthnCredentials = user.credentialManager()
                .getStoredCredentialsStream()
                .filter(cred -> WebAuthnCredentialModel.TYPE_PASSWORDLESS.equals(cred.getType()))
                .toList();

        if (webAuthnCredentials.isEmpty()) {
            return buildErrorResponse(Response.Status.NOT_FOUND, "No passkey found for user");
        }

        logger.info("Generate challenge");
        List<String> credentialIds = new ArrayList<>();
        for (CredentialModel webAuthnCredential : webAuthnCredentials) {
            WebAuthnCredentialModel credentialModel = WebAuthnCredentialModel.createFromCredentialModel(webAuthnCredential);
            // Convert byte[] to Base64 string
            String credentialIdBase64 = credentialModel.getWebAuthnCredentialData().getCredentialId();
            credentialIds.add(credentialIdBase64);
        }

        // Generating a challenge
        String challengeBase64 = Base64UrlUtil.encodeToString(WebAuthnUtil.generateChallenge());

        // Create tabId and authSession
        String tabId = UUID.randomUUID().toString();

        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
        RootAuthenticationSessionModel rootSession = authSessionManager.createAuthenticationSession(realm, true);
        AuthenticationSessionModel authSession = rootSession.getAuthenticationSession(client, tabId);

        //Store challenge in auth session
        long ttl = KeycloakConsts.CHALLENGE_TTL_MINUTE * 60 * 1000;
        long expireAt = LocalDateTime.now().getNano() + ttl;

        authSession.setAuthNote(KeycloakConsts.CHALLENGE_KEY, challengeBase64);
        authSession.setAuthNote(KeycloakConsts.CHALLENGE_EXPIRY_KEY, String.valueOf(expireAt));


        logger.info("--------------Generate challenge authentication completed--------------");

        // Return JSON response
        Map response = Map.of(WebAuthnConstants.CHALLENGE, challengeBase64,
                "allowCredentials", credentialIds,
                WebAuthnConstants.RP_ID, WebAuthnUtil.getRpID(session.getContext()), "tabId", authSession.getTabId(), "authSessionId", rootSession.getId());

        return Response.ok(response)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .build();
    }

    @POST
    @Path(KeycloakConsts.PASSKEY_AUTHENTICATION_PATH)
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticatePasskey(PasskeyRequest request) throws UnsupportedEncodingException, JsonProcessingException {

        logger.info("----------------Authentication-------------------");
        RealmModel realm = session.getContext().getRealm();

        logger.info("Validation realm");
        if (realm == null) return missingRealmResponse();

        UserModel user = session.users().getUserByUsername(realm, request.getUsername());
        ClientModel client = realm.getClientByClientId(request.getClientId());

        logger.info("Validation user.");
        if (user == null) {
            return buildErrorResponse(Response.Status.NOT_FOUND, "User not found");
        }

        logger.info("Validation client");
        if (client == null) {
            return buildErrorResponse(Response.Status.BAD_REQUEST, "Missing client context");
        }

        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
        AuthenticationSessionModel authSession = authSessionManager.getAuthenticationSessionByIdAndClient(realm, request.getSessionId(), client, request.getTabId());

        logger.info("Validation session");
        if (Objects.isNull(authSession)) {
            return buildErrorResponse(Response.Status.BAD_REQUEST, "Invalid session");
        }

        logger.info("Validation passkey registed");
        WebAuthnCredentialModel webAuthnCredential = getWebAuthnCredential(user, request.getCredentialId());
        if (webAuthnCredential == null)
            return buildErrorResponse(Response.Status.NOT_FOUND, "No passkey found for user");

        byte[] credentialId = Base64UrlUtil.decode(request.getCredentialId());
        byte[] authenticatorData = Base64UrlUtil.decode(request.getAuthenticatorData());
        byte[] signature = Base64UrlUtil.decode(request.getSignature());

        boolean isValid = isPasskeyValid(authSession, credentialId, authenticatorData, request.getClientDataJSON(), signature, user, realm);
        logger.info("Passkey validation result -> " + isValid);

        if (isValid)
            return generateTokensResponse(user, request.getClientId());
        else
            return buildErrorResponse(Response.Status.UNAUTHORIZED, "Invalid passkey");

    }

    private UserModel getUserByUsername(RealmModel realm, String username) {
        return session.users().getUserByUsername(realm, username);
    }

    private WebAuthnCredentialModel getWebAuthnCredential(UserModel user, String credentialId) {
        var credentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
        var credList = credentials.toList();
        return (credList.get(0) != null) ? WebAuthnCredentialModel.createFromCredentialModel(credList.get(0)) : null;
    }

    private boolean isPasskeyValid(AuthenticationSessionModel authSession, byte[] credentialId,
                                   byte[] authenticatorData, String clientDataJSON,
                                   byte[] signature, UserModel user, RealmModel realm) throws JsonProcessingException, UnsupportedEncodingException {
        // Decode the Base64 string
        logger.info("------------------Validate passkey------------------");
        byte[] decodedBytes = Base64UrlUtil.decode(clientDataJSON);
        String decodedClientDataJSON = new String(decodedBytes, "UTF-8");

        // Deserialize the decoded JSON string into a JsonNode
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode clientData = objectMapper.readTree(decodedClientDataJSON);
        String requestChallenge = Objects.nonNull(clientData.get(WebAuthnConstants.CHALLENGE)) ? clientData.get(WebAuthnConstants.CHALLENGE).asText() : null;

        String storedChallenge = authSession.getAuthNote(KeycloakConsts.CHALLENGE_KEY);
        String expiryStr = authSession.getAuthNote(KeycloakConsts.CHALLENGE_EXPIRY_KEY);
        if (Objects.isNull(storedChallenge) || Objects.isNull(expiryStr)
                || Long.parseLong(expiryStr) < LocalDateTime.now().getNano()
                || !StringUtils.equals(requestChallenge, storedChallenge)) {
            logger.error("Challenge mismatch or not found.");
            return false;
        }

        Origin origin = new Origin(clientData.get("origin").asText());
        String rpId = clientData.get("origin").asText().replace("http://", "").replace("https://", "").split(":")[0];

        Challenge challenge = new DefaultChallenge(storedChallenge);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        boolean isUVFlagChecked = WebAuthnConstants.OPTION_REQUIRED.equals(realm.getWebAuthnPolicyPasswordless().getUserVerificationRequirement());
        var authReq = new AuthenticationRequest(credentialId, authenticatorData, Base64UrlUtil.decode(clientDataJSON),
                signature);
        var authParams = new WebAuthnCredentialModelInput.KeycloakWebAuthnAuthenticationParameters(serverProperty, isUVFlagChecked);

        var cred = new WebAuthnCredentialModelInput(WebAuthnCredentialModel.TYPE_PASSWORDLESS);

        cred.setAuthenticationRequest(authReq);
        cred.setAuthenticationParameters(authParams);
        logger.info("cred -> " + cred);
        logger.info("isValid -> " + user.credentialManager().isValid(cred));
        return user.credentialManager().isValid(cred);
    }

    private Response generateTokensResponse(UserModel user, String clientId) {
        try {
            RealmModel realm = session.getContext().getRealm();
            logger.info("realm --> " + realm.getName());

            ClientModel client = realm.getClientByClientId(clientId);
            if (client == null) {
                logger.error("Client not found for client_id: {}", new String[]{clientId});
                return buildErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Client not found");
            }
            logger.info("client --> " + client.getName());

            // ✅ Set the client explicitly in the Keycloak session context
            session.getContext().setClient(client);  // <-- This is crucial

            // Create user session
            UserSessionModel userSession = session.sessions().createUserSession(
                    realm, user, user.getUsername(), "127.0.0.1", "form", true, null, null);
            logger.info("userSession --> " + userSession);

            // Create client session
            AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
            if (clientSession == null) {
                clientSession = session.sessions().createClientSession(realm, client, userSession);
            }

            // Create ClientSessionContext with scope parameter
            ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(
                    clientSession, "", session);

            // ✅ Ensure the client context is not null before generating the token
            if (session.getContext().getClient() == null) {
                logger.error("Client context is still null after setting.");
                return buildErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Client context is null");
            }

            // Generate access token
            TokenManager tokenManager = new TokenManager();
            AccessToken accessToken = tokenManager.createClientAccessToken(
                    session, realm, client, user, userSession, clientSessionCtx);

            String accessTokenString = session.tokens().encode(accessToken);
            RefreshToken refreshToken = new RefreshToken(accessToken);
            String refreshTokenString = session.tokens().encode(refreshToken);

            logger.info("Successfully generated token for user: " + user.getUsername());
            Map tokenResponse = Map.of(OAuth2Constants.ACCESS_TOKEN, accessTokenString,
                    OAuth2Constants.REFRESH_TOKEN, refreshTokenString,
                    OAuth2Constants.EXPIRES_IN, accessToken.getExp());
            return Response.ok(tokenResponse)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .build();
        } catch (Exception e) {
            logger.error("Token generation failed: " + e.getMessage(), e);
            return buildErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Token generation failed: " + e.getMessage());
        }
    }

    private Response buildErrorResponse(Response.Status status, String message) {
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("{\"error\": \"Invalid passkey\"}")
                .build();
    }

    protected WebAuthnRegistrationManager createWebAuthnRegistrationManager() {
        return new WebAuthnRegistrationManager(
                Arrays.asList(
                        new NoneAttestationStatementValidator(),
                        new PackedAttestationStatementValidator(),
                        new TPMAttestationStatementValidator(),
                        new AndroidKeyAttestationStatementValidator(),
                        new AndroidSafetyNetAttestationStatementValidator(),
                        new FIDOU2FAttestationStatementValidator()
                ), this.certPathTrustValidator,
                new DefaultSelfAttestationTrustworthinessValidator(),
                Collections.emptyList(),
                new ObjectConverter()
        );
    }

    private Response missingRealmResponse() {
        return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"Missing realm context. Use /realms/{realm}/...\"}").build();
    }

    private Response userUnauthorized() {
        return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"User unauthorized\"}").build();
    }

    private Response challengeExpired() {
        return Response.status(Response.Status.BAD_REQUEST).entity("{\"error\": \"Challenge invalid or expired\"}").build();
    }
}

