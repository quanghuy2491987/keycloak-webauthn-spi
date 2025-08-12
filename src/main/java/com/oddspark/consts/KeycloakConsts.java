package com.oddspark.consts;

public class KeycloakConsts {
    public static final String PASSKEY_ID = "passkey";

    public static final String CHALLENGE_KEY = "user_generated_challenge";

    public static final String CHALLENGE_EXPIRY_KEY = "user_generated_challenge_expiry";

    public static final int CHALLENGE_TTL_MINUTE = 5;

    public static final String PASSKEY_REGEX = "^/realms/[^/]+/passkey(?:/.*)?$";

    public static final String PASSKEY_ROOT_PATH = "/passkey";

    public static final String PASSKEY_GET_CHALLENGE_PATH = "/challenge";

    public static final String PASSKEY_REGISTER_PATH = "/register";

    public static final String PASSKEY_GET_CHALLENGE_AUTHENTICATION_PATH = "/authenticate/challenge";

    public static final String PASSKEY_AUTHENTICATION_PATH = "/authenticate";
}

