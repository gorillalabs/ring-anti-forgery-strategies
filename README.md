# Ring-Anti-Forgery

[![Build Status](https://travis-ci.org/ring-clojure/ring-anti-forgery-strategies.svg?branch=master)](https://travis-ci.org/ring-clojure/ring-anti-forgery-strategies)

Ring middleware extension that prevents [CSRF][1] attacks by via 
an [encrypted token](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Encrypted_Token_Pattern).

Make sure to always use tls (https), here especially use it to prevent replay attacks!

[1]: http://en.wikipedia.org/wiki/Cross-site_request_forgery

## Install

Add the following dependency to your `project.clj`:

    [ring/ring-anti-forgery "1.1.0"]
    [ring/ring-anti-forgery-strategies "1.1.0"]

## Usage

The `wrap-anti-forgery` middleware should be applied to your Ring
handler.

Any request that isn't a `HEAD` or `GET` request will now require an
anti-forgery token, or an "access denied" response will be returned.

As default, a synchronizer token pattern is used and the token is
bound to the session.
 

You can use the encrypted token mode withoud the `wrap-session` middleware.

You need to set some options on the `wrap-anti-forgery` middleware:

```clojure
(require '[ring.middleware.anti-forgery.strategy.signed-token :as signed-token]
         '[ring.middleware.anti-forgery :refer :all]
         '[buddy.core.keys :as keys]
         '[clj-time.core :as time])

(def ^:private signed-token-sms (signed-token/->SignedTokenSMS
                                  (keys/public-key "dev-resources/test-certs/pubkey.pem")
                                  (keys/private-key "dev-resources/test-certs/privkey.pem" "antiforgery")
                                  (time/hours 1)
                                  :identity))

(def app
  (-> handler
      wrap-anti-forgery {:strategy signed-token-sms}))
```

Public and private keys were created using commands from https://funcool.github.io/buddy-sign/latest/#generate-keypairs

Generate aes256 encrypted private key:
       
    openssl genrsa -aes256 -out privkey.pem 2048
       
Generate public key from previously created private key:
       
    openssl rsa -pubout -in privkey.pem -out pubkey.pem
       
Maybe you need to install the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files.


## License

Copyright © 2018 Christian Betz

Distributed under the MIT License, the same as Ring.
