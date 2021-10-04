# OpenID Connect Via Enclave
A division of OpenID Connect authentication between an untrusted operating system, and a trusted execution environment.

## Getting started
### Preparation
Clone this repository.

Then, create the following file: `host/src/main/resources/application.yml`.

Into the `application.yml` file, paste the following:

```
spring:
    security:
        oauth2:
            client:
                provider:
                    mocklab:
                        authorization-uri: https://oauth.mocklab.io/oauth/authorize
                        token-uri: https://oauth.mocklab.io/oauth/token
                        user-info-uri: https://oauth.mocklab.io/userinfo
                        user-name-attribute: sub
                        jwk-set-uri: https://oauth.mocklab.io/.well-known/jwks.json
                registration:
                    mock-oidc:
                        provider: mocklab
                        authorization-grant-type: authorization_code
                        scope: openid, profile, email
                        redirect-uri: "{baseUrl}/{action}/oauth2/code/{registrationId}"
                        clientId: clientid
                        clientSecret: clientsecret
```

here, the openid connect provider is mocklab, and in their particular case you can replace the
`<your-client-id>` and `<your-client-secret` with anything. 
if you would like to use a different op, change the contents of this file accordingly.

download [the conclave 1.1 sdk (for community)](https://conclave.net/get-conclave/)
and unzip it. set `conclaverepo` in `gradle.properties` 
to match the path to the `repo/` directory inside the unpacked sdk.

### running
#### 1. starting
run the spring server with `./gradlew host:bootrun`.

#### 2. signing in
in a browser, navigate to 
`http://localhost:8080/oauth2/authorization/mock-oidc?pubkey=a946160f377bc3591cd0224bcc38ec120f2c16ab7705ccdb3ddff372c89e7e24`

in the url, `mock-oidc` is the registered op from the `application.yml` file, and the value of `pubkey`
is the hex-encoded public key, corresponding to a private key that is the sha256 hash of the byte representation
of the string "secret". 
it doesn't really matter what this `pubkey` value is, as long as it is the public key used to encrypt messages sent later.
the value of `pubkey` used here is the same that is printed to the console when running the spring server,
printed as `getencoded: a946160f377bc3591cd0224bcc38ec120f2c16ab7705ccdb3ddff372c89e7e24`.

the mocklab "sign in" page that you will see is just a facade; 
you can enter whatever value you want for the email and password (or even no value), 
and the auth process will continue.

once you sign in, you will be taken to page that says *whitelabel error page*, 
which just means that there isn't an explicit page served and spring creates this for us.

#### 3. sending a message
after you have signed in, you can send messages to the enclave.
open up an inspection tool in your browser and copy the value of the `jsessionid` cookie.
in firefox, you can do that this way:
* right click anywhere on the page
* in the context menu, select `inspect`
* navigate to the `storage` tab in the horizontal menu
* on the left in the vertical menu, click `cookies`
* in the list of buttons that appears below the `cookies` tab, click `http://localhost:8080`
* copy the value of `jsessionid` to your clipboard from the table in the middle of the inspection window

now, send a get request with the same `jsessionid` cookie and a `plain/text` body of

```
002800000000000000000000076d657373616765000000124820f3376ae6b2f2034d3b7a4b48a77800017190de8aadc3be261cc638233716804dfd899f3469c53d399ad3c5bc16ce5103c04938c9d0986e8f0e713fabf3c418a1688a475d4d1bd8920cec04d77a99c1f2f0df3a1aaf1a8f47f0bf015f19ba12a8b0568022c40ea852d78912018c5007f1002a1490018175f7323d53c66503352063f4dc4944e776b873cef83fa2d8ada709bf926a4fc316094e5bb50d0012b51fbf7db1dae6a5ef536b2887f2f2071a43
```

to `localhost:8080/user/message`. you can do this with postman or curl.

the thing that you put in the body is a mail containing the string "test message", 
encrypted by the same key-pair whose public key you put in the `pubkey` url-encoded argument in step 2. 
this is also generated and printed to the terminal when you run the server,
printed right after `public key: curve25519publickey(a946160f377bc3591cd0224bcc38ec120f2c16ab7705ccdb3ddff372c89e7e24)`.

in curl, the command to send that message could be:
```shell
curl -h "content-type: text/plain" --request get  \
-b jsessionid=fb35de9392ca488c1684a3c573bd4785 \
-d 002800000000000000000000076d657373616765000000124820f3376ae6b2f2034d3b7a4b48a77800017190de8aadc3be261cc638233716804dfd899f3469c53d399ad3c5bc16ce5103c04938c9d0986e8f0e713fabf3c418a1688a475d4d1bd8920cec04d77a99c1f2f0df3a1aaf1a8f47f0bf015f19ba12a8b0568022c40ea852d78912018c5007f1002a1490018175f7323d53c66503352063f4dc4944e776b873cef83fa2d8ada709bf926a4fc316094e5bb50d0012b51fbf7db1dae6a5ef536b2887f2f2071a43 \
localhost:8080/user/message
```
of course, replace the value of jsessionid with whatever the value is from your browser.

however you send that request, you will get an empty 200 response if everything is successful.
navigating to the terminal in which you ran the host in step 1, you will see a line `enclave> test message`.
currently, the enclave simply prints the message to the terminal after verifying and decrypting it.

### abusing!
#### replay attack
while the server is still running, repeat step 3 to send the same article of mail again.
you will see that the enclave throws an `illegalstateexception` because it detected a replay.
each message encrypted as mail will have an increasing counter that prevents replay attacks.
this is the same thing that would happen if a malicious host tried to replay a message from a signed-in user.

#### mail forgery
repeat steps 1 and 2, but this time for step 2 replace the 
`pubkey=a946160f377bc3591cd0224bcc38ec120f2c16ab7705ccdb3ddff372c89e7e24`
with `pubkey=abc123`. this represents a case where the user's public key is `abc123`.

repeat step 3. you will see that the enclave throws another error:
`java.lang.illegalargumentexception: invalid public key!`.
this is because the public key hash in the openid connect token doesn't match the public key with which
the mail was encrypted. this is what occurs if a host tries to inject mail made by itself as if from a user,
or if it mixes up mail sent by different users.

the only way for mail to be accepted by the enclave is for it to be in agreement with the nonce in the openid connect
token, and the only way for that to be the case is for the user to follow the 302 redirect and sign in.
any client-side implementation should verify the value of the nonce in the redirect matches the `pubkey`
value in the request.

## modifying
all logic for verifying mail based on the routinghint (the oidc token) is contained in VerifierEnclave.
VerfierEnclave is an abstract class, and after it performs the verification it calls an unimplemented `handlemessage`
method with trusted, decrypted message bytes.

to add some functionality to the enclave, extend VerifierEnclave and implement `handlemessage` with whatever custom logic.
the motivation behind using inheritance is that it preserves access to things like `postmail` and `postoffice`.
currently, `requesthandler.java` is the enclave class that is being used; any replacement for it must
be reflected in `oidcserverapplication` in the `enclave` bean 
(change `string enclavename="com.example.enclave.requesthandler"` 
to match the fully qualified name of the enclave that you use).

note that conclave only allows one enclave class per gradle module, 
so whatever custom class you create will have to replace RequestHandler (you will have to delete it).

also, VerifierEnclave uses avian instead of GraalVM because Graal does not support nimbus jwt parsing etc
that VerifierEnclave needs to do. avian is deprecated.

**NOTE** you can change enclave modes using the `-PenclaveMode` command-line argument.
Use `-PenclaveMode=mock` on Windows to run mock enclaves. 
Use`-PenclaveMode=release` in release to use the real hardware enclave (if it is supported)

## more stuff:
high level design/architecture/overview with reasoning: [doc/DESIGN.md](doc/DESIGN.md)