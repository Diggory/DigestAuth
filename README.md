# Digest Auth Sample

A simple demo project which uses [AsyncHTTPClient](https://github.com/swift-server/async-http-client) to request a resource from a web server that requires diget-auth authentication. 

[Wikipedia article on Digest Auth](https://en.wikipedia.org/wiki/Digest_access_authentication)

## Pseudo Code
 
 
From a [StackOverflow question](https://stackoverflow.com/questions/5288150/is-digest-authentication-possible-with-jquery/5288679#5288679)
 

1. Make basic HTTP request to remote server (no auth in header)
2. Server responds with a "401 Unauthorized" status code and a WWW-Authenticate header field (the *digest-challenge*)
3. Make 2nd request for same resource but with an Authorization header field in response to the challenge (*the digest-response*)

Each [WWW-Authenticate response header](https://www.rfc-editor.org/rfc/rfc2617#section-3.2.2) field has the syntax:

```
 challenge        =  "Digest" digest-challenge
 digest-challenge  = 1#( realm | [ domain ] | nonce |
					 [ opaque ] |[ stale ] | [ algorithm ] |
					 [ qop-options ] | [auth-param] )
```

So you need to parse the digest-challenge to get the parameters to be able to generate a digest-reponse for the Authorization request header field with the following syntax:

```
 credentials      = "Digest" digest-response
 digest-response  = 1#( username | realm | nonce | digest-uri
				 | response | [ algorithm ] | [cnonce] |
				 [opaque] | [message-qop] |
					 [nonce-count]  | [auth-param] )
```
 
 That section also describes how the digest-response parameters are calculated. In particular, you will probably need an MD5 implementation as that’s the most commonly used algorithm for this authentication scheme.
