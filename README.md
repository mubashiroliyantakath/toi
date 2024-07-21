Traefik Oauth Intrespection

This traefik plugin can be used introspect API requests. It can be used to validate the OAuth2 access tokens via introspection.

It requires the following configuration fields:
```yaml
    clientid: "oauth-client"
    clientsecret: "secret"
    issuer: https://oauth-server/
```

Please see the [dynamic configuration file](./example/dynamic.yaml) in the example folder for more details.
