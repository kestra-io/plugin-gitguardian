package io.kestra.plugin.gitguardian;

/** Shared `@Schema` wording for the connection properties, which a task and a trigger must both redeclare. */
public interface GitGuardianConnectionInterface {
    String DEFAULT_API_URL = "https://api.gitguardian.com";

    String API_URL_TITLE = "GitGuardian API URL";
    String API_URL_DESCRIPTION = """
        Base URL of the GitGuardian API for your workspace: `https://api.gitguardian.com` (US, default), \
        `https://api.eu1.gitguardian.com` (EU), or `https://<your-instance>/exposed` for a self-hosted GitGuardian. \
        The `/v1` prefix is appended automatically.
        """;

    String API_KEY_TITLE = "GitGuardian API key";
    String API_KEY_DESCRIPTION = """
        Personal access token or service account token created in the GitGuardian dashboard under API > Personal \
        access tokens / Service accounts. The token needs the scopes required by the tasks and triggers you use, \
        for example `scan`, `incidents:read`, `incidents:write`, or `honeytokens:read`. Sent as \
        `Authorization: Token <key>`; never logged or included in error messages.
        """;
}
