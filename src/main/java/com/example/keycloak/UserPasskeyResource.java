package com.example.keycloak;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
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
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.WebAuthnConstants;
import org.keycloak.common.util.Base64Url;
import org.keycloak.credential.*;

import org.keycloak.models.*;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.util.DefaultClientSessionContext;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Path("/passkey")
public class UserPasskeyResource {

    private final KeycloakSession session;
    private final CertPathTrustworthinessValidator certPathTrustValidator ;
    private static final Logger logger = Logger.getLogger(UserPasskeyResource.class);

    @Inject
    public UserPasskeyResource(KeycloakSession session) {
        this.session = session;
        this.certPathTrustValidator  = new NullCertPathTrustworthinessValidator();
    }

    @GET
    @Path("challenge")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChallenge(@QueryParam("username") String username) {
        logger.info("--------------Generating WebAuthn Challenge--------------");
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) return missingRealmResponse();

        WebAuthnPolicy policy = WebAuthnUtil.getWebAuthnPolicy(session.getContext());
        List<String> signatureAlgorithmsList = policy.getSignatureAlgorithm();
        // Convert human-readable algorithms to their COSE identifier form
        List<Long> signatureAlgorithms = WebAuthnUtil.convertSignatureAlgorithms(signatureAlgorithmsList);

        // Generate a new challenge
        byte[] challengeBase64 = WebAuthnUtil.generateChallenge();
        String rpId = WebAuthnUtil.getRpID(session.getContext());
        String userId = Base64Url.encode(username.getBytes(StandardCharsets.UTF_8));


        Map response = Map.of(WebAuthnConstants.CHALLENGE, Base64UrlUtil.encodeToString(challengeBase64),
                WebAuthnConstants.USER_ID, userId,
                WebAuthnConstants.USER_NAME, username,
                WebAuthnConstants.SIGNATURE_ALGORITHMS, signatureAlgorithms,
                WebAuthnConstants.RP_ID, rpId);


        // Return the challenge as JSON response
        return Response.ok(response)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .build();
    }

    @GET
    @Path("/get-credential-id")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCredentialId(@QueryParam("username") String username) {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserByUsername(realm, username);

        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\": \"User not found\"}")
                    .build();
        }

        // Get all WebAuthn credentials for the user
        List<CredentialModel> webAuthnCredentials = user.credentialManager()
                .getStoredCredentialsStream()
                .filter(cred -> WebAuthnCredentialModel.TYPE_PASSWORDLESS.equals(cred.getType()))
                .toList();

        if (webAuthnCredentials.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\": \"No passkey found for user\"}")
                    .build();
        }

        List<String> credentialIds = new ArrayList<>();
        for (CredentialModel webAuthnCredential : webAuthnCredentials) {
            WebAuthnCredentialModel credentialModel = WebAuthnCredentialModel.createFromCredentialModel(webAuthnCredential);
            // Convert byte[] to Base64 string
            String credentialIdBase64 = credentialModel.getWebAuthnCredentialData().getCredentialId();
            credentialIds.add(credentialIdBase64);
        }

        // Generating a challenge
        String challengeBase64 = Base64UrlUtil.encodeToString(WebAuthnUtil.generateChallenge());
        // Store challenge in user attributes
        user.setSingleAttribute("webauthn-challenge", challengeBase64);

        // Return JSON response
        Map response = Map.of(WebAuthnConstants.CHALLENGE, challengeBase64,
                "allowCredentials", credentialIds,
                WebAuthnConstants.RP_ID, WebAuthnUtil.getRpID(session.getContext()));

        return Response.ok(response)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .build();
    }

    @POST
    @Path("register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response savePasskey(PasskeyRequest request) throws JsonProcessingException, UnsupportedEncodingException {
        if (request.getUsername() == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Username and passkey are required")
                    .build();
        }

        // Get the current realm
        RealmModel realm = session.getContext().getRealm();
        List<UserModel> users = session.users()
                .searchForUserStream(realm, request.getUsername())
                .toList();

        if (users.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("User not found")
                    .build();
        }

        UserModel user = users.get(0);

        String base64ClientDataJSON = request.getClientDataJSON();

        byte[] decodedBytes = Base64.getDecoder().decode(base64ClientDataJSON);
        String decodedClientDataJSON = new String(decodedBytes, "UTF-8");

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode clientData = objectMapper.readTree(decodedClientDataJSON);

        Origin origin = new Origin(clientData.get("origin").asText());
        String rpId = clientData.get("origin").asText().replace("http://", "").replace("https://", "").split(":")[0];

        Challenge challenge = new DefaultChallenge(clientData.get("challenge").asText());

        Set<Origin> originSet = new HashSet<>();
        originSet.add(origin);
        ServerProperty serverProperty = new ServerProperty(originSet, rpId, challenge, null);
        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, true);

        byte[] attestationObject = Base64.getDecoder().decode(request.getAttestationObject());
        byte[] clientDataJSON = Base64.getDecoder().decode(request.getClientDataJSON());
        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON);

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
        WebAuthnCredentialModel credentialModel = webAuthnCredProvider.getCredentialModelFromCredentialInput(credential, user.getUsername());

        WebAuthnCredentialModel webAuthnCredentialModel = WebAuthnCredentialModel.createFromCredentialModel(credentialModel);

        user.credentialManager().createStoredCredential(webAuthnCredentialModel);

        Map responsea = Map.of("success",true, "message", "Passkey stored successfully");
        return Response.status(Response.Status.CREATED)
                .entity(responsea)
                .build();
    }

    @POST
    @Path("authenticate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticatePasskey(PasskeyRequest request) throws UnsupportedEncodingException, JsonProcessingException {
        RealmModel realm = session.getContext().getRealm();

        UserModel user = getUserByUsername(realm, request.getUsername());
        if (user == null)
            return buildErrorResponse(Response.Status.NOT_FOUND, "User not found");

        WebAuthnCredentialModel webAuthnCredential = getWebAuthnCredential(user, request.getCredentialId());
        if (webAuthnCredential == null)
            return buildErrorResponse(Response.Status.NOT_FOUND, "No passkey found for user");

        byte[] credentialId = Base64UrlUtil.decode(request.getCredentialId());
        byte[] authenticatorData = Base64UrlUtil.decode(request.getAuthenticatorData());
        byte[] signature = Base64UrlUtil.decode(request.getSignature());
        String clientDataJSON = request.getClientDataJSON();
        String challenge = request.getChallenge();

        boolean isValid = isPasskeyValid(credentialId, authenticatorData, clientDataJSON, signature, challenge, user, realm);
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

    private boolean isPasskeyValid(byte[] credentialId, byte[] authenticatorData, String clientDataJSON, byte[] signature, String challengeRequest, UserModel user, RealmModel realm) throws JsonProcessingException, UnsupportedEncodingException {
        // Decode the Base64 string
        byte[] decodedBytes = Base64UrlUtil.decode(clientDataJSON);
        String decodedClientDataJSON = new String(decodedBytes, "UTF-8");

        String storedChallenge = user.getFirstAttribute("webauthn-challenge");
        if (storedChallenge == null || !storedChallenge.equals(challengeRequest)) {
            logger.error("Challenge mismatch or not found.");
            return false;
        }

        // Deserialize the decoded JSON string into a JsonNode
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode clientData = objectMapper.readTree(decodedClientDataJSON);

        Origin origin = new Origin(clientData.get("origin").asText());
        String rpId = clientData.get("origin").asText().replace("http://", "").replace("https://", "").split(":")[0];
        Challenge challenge = new DefaultChallenge(storedChallenge);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        boolean isUVFlagChecked = WebAuthnConstants.OPTION_REQUIRED.equals(realm.getWebAuthnPolicyPasswordless().getUserVerificationRequirement());
        var authReq = new AuthenticationRequest(credentialId, authenticatorData,  Base64UrlUtil.decode(clientDataJSON),
                signature);
        var authParams = new WebAuthnCredentialModelInput.KeycloakWebAuthnAuthenticationParameters(serverProperty, isUVFlagChecked);;
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
                logger.error("Client not found for client_id: demo-client");
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
            logger.info("accessToken -> " + accessToken);

            String accessTokenString = session.tokens().encode(accessToken);
            RefreshToken refreshToken = new RefreshToken(accessToken);
            String refreshTokenString = session.tokens().encode(refreshToken);
            logger.info("refreshToken -> " + refreshToken);

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

}
