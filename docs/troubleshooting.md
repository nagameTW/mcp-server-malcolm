# Troubleshooting

## When the first call fails

Three failures account for nearly every first run. All three were reproduced with `malcolm_ping`; the text is verbatim.

**Self-signed certificate with `MALCOLM_SSL_VERIFY` unset.** This is the most likely one, because the default is verify-on and a stock Malcolm's certificate does not pass verification:

```
Error executing tool malcolm_ping: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1082)
```

The `_ssl.c` line number tracks your interpreter, not this server: the same failure reads `_ssl.c:1016` on Python 3.11, which is what the Docker image and the CI floor both run.

The message never names `MALCOLM_SSL_VERIFY`, so it is easy to read as a broken install. Fix it by installing a certificate with a correct SAN and pointing `MALCOLM_SSL_VERIFY` at its CA bundle, or, on an isolated lab only, by setting `MALCOLM_SSL_VERIFY=false`.

**Wrong password.** Clear and actionable — the status and the URL are both in the message:

```
Error executing tool malcolm_ping: Client error '401 Unauthorized' for url 'https://malcolm.example/mapi/ping'
For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401
```

Read the host before the password. A 401 from `https://localhost` when your Malcolm lives elsewhere means neither `MALCOLM_URL` nor `MALCOLM_BASE_URL` reached the server's environment, so it fell back to the default and asked the wrong machine.

**Unreachable host** (typo'd `MALCOLM_URL`, firewalled port, wrong scheme):

```
Error executing tool malcolm_ping: ConnectTimeout for https://192.0.2.99:9999/mapi/ping
```

The two unreachable cases read differently. A port that actively refuses the connection answers `All connection attempts failed`; a host that simply never replies raises `ConnectTimeout`, whose `str()` httpx leaves empty — up to 1.0.1 that reached the caller as a bare `Error executing tool malcolm_ping: ` with nothing after the colon. The exception name and target are filled in now. Credentials embedded in `MALCOLM_URL` are stripped from that URL before it is shown.
