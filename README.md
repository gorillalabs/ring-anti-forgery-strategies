# Ring-Anti-Forgery Strategies

[![Build Status](https://travis-ci.org/ring-clojure/ring-anti-forgery-strategies.svg?branch=master)](https://travis-ci.org/ring-clojure/ring-anti-forgery-strategies)

Ring middleware extension that prevents [CSRF][1] attacks by via 
an [encrypted token][2].

[1]: http://en.wikipedia.org/wiki/Cross-site_request_forgery
[2]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Encrypted_Token_Pattern


## Install

Add the following dependency to your `project.clj`:

    [ring/ring-anti-forgery "1.2.0"]
    [gorillalabs/ring-anti-forgery-strategies "1.2.0"]

## Usage

Use the `ring.middleware.anti-forgery/wrap-oauth2` middleware, but add
the `:strategy` option, using one of the two strategies based upon
encryption or cryptographic signing.

### Encrypted token

For a symmetrically encrypted token use 

```clojure
(require '[ring.middleware.anti-forgery.encrypted-token :as encrypted-token]
         '[ring.middleware.anti-forgery :refer :all]
         '[buddy.core.keys :as keys]
         '[clj-time.core :as time])

(let [expires-in-one-hour      (time/hours 1))
      secret                   "secret-to-validate-token-after-decryption-to-make-sure-i-encrypted-stuff")
      encrypted-token-strategy (encrypted-token/encrypted-token
                                     secret
                                     expires-in-one-hour :identity)]

(wrap-anti-forgery handler {:strategy encrypted-token-strategy})
```

### Signed token

To cryptographically sign a token, you need a public-/private keypair.

Public and private keys were created using commands from 
[buddy-sign dokumentation](https://funcool.github.io/buddy-sign/latest/#generate-keypairs).

> Generate aes256 encrypted private key:
>       
>     openssl genrsa -aes256 -out privkey.pem 2048
>       
> Generate public key from previously created private key:
>        
>     openssl rsa -pubout -in privkey.pem -out pubkey.pem
       
Maybe you need to install the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files.


```clojure
(require '[ring.middleware.anti-forgery.signed-token :as signed-token]
         '[ring.middleware.anti-forgery :refer :all]
         '[buddy.core.keys :as keys]
         '[clj-time.core :as time])

(let [signed-token-strategy (signed-token/signed-token
                              (keys/public-key "dev-resources/test-certs/pubkey.pem")
                              (keys/private-key "dev-resources/test-certs/privkey.pem" "antiforgery")
                              (time/hours 1)
                              :identity)]

(def app
  (-> handler
      wrap-anti-forgery {:strategy signed-token-sms})))
```


Make sure to always use tls (https) for your services, here especially
use it to prevent replay attacks!


## License

Copyright © 2018 Christian Betz

Distributed under the MIT License, the same as Ring.
