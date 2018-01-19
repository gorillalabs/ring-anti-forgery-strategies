# Ring-Anti-Forgery

[![Build Status](https://travis-ci.org/ring-clojure/ring-anti-forgery.svg?branch=master)](https://travis-ci.org/ring-clojure/ring-anti-forgery)

Ring middleware that prevents [CSRF][1] attacks by via a
randomly-generated anti-forgery [synchronizer token](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Synchronizer_.28CSRF.29_Tokens)
or by implementing an [encrypted token](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Encrypted_Token_Pattern).

Make sure to always use tls (https), here especially use it to prevent replay attacks!

[1]: http://en.wikipedia.org/wiki/Cross-site_request_forgery

## Install

Add the following dependency to your `project.clj`:

    [ring/ring-anti-forgery "1.1.0"]

## Usage

The `wrap-anti-forgery` middleware should be applied to your Ring
handler.

Any request that isn't a `HEAD` or `GET` request will now require an
anti-forgery token, or an "access denied" response will be returned.

As default, a synchronizer token pattern is used and the token is
bound to the session.

In both synchronizer and encrypted token mode the token is accessible
via the `*anti-forgery-token*` var.
 
### Synchronizer token
 
You must use `wrap-anti-forgery` middleware inside of the standard
`wrap-session` middleware in Ring:

```clojure
(use 'ring.middleware.anti-forgery
     'ring.middleware.session)

(def app
  (-> handler
      wrap-anti-forgery
      wrap-session))
```

### Encrypted token

You can use the encrypted token mode withoud the `wrap-session` middleware.

You need to set some options on the `wrap-anti-forgery` middleware:

```clojure
(use 'ring.middleware.anti-forgery
     'buddy.core.keys
     'clj-time.core)

(def app
  (-> handler
      wrap-anti-forgery {:encrypted-token? true?
                         :public-key       (public-key "certs/pubkey.pem")
                         :private-key      (private-key "certs/privkey.pem" "key-password")
                         :secret           "secret-to-validate-token-after-decryption-to-make-sure-i-encrypted-stuff"
                         :expiration       (hours 1)}))
```

Public and private keys were created using commands from https://funcool.github.io/buddy-sign/latest/#generate-keypairs

Generate aes256 encrypted private key:
       
    openssl genrsa -aes256 -out privkey.pem 2048
       
Generate public key from previously created private key:
       
    openssl rsa -pubout -in privkey.pem -out pubkey.pem
       
Maybe you need to install the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files.

## Token usage

By default the middleware looks for the anti-forgery token in the
`__anti-forgery-token` form parameter, which can be added to your
forms as a hidden field. For convenience, this library provides a
function to generate the HTML of that hidden field:

```clojure
(use 'ring.util.anti-forgery)

(anti-forgery-field)  ;; returns the HTML for the anti-forgery field
```

The middleware also looks for the token in the `X-CSRF-Token` and
`X-XSRF-Token` header fields, which are commonly used in AJAX
requests.

This behavior can be customized further by supplying a function to the
`:read-token` option. This function is passed the request map, and
should return the anti-forgery token found in the request.

```clojure
(defn get-custom-token [request]
  (get-in request [:headers "x-forgery-token"]))

(def app
  (-> handler
      (wrap-anti-forgery {:read-token get-custom-token})
      (wrap-session)))
```

## Error handling

It's also possible to customize the error response returned when the
token is invalid or missing:

```clojure
(def custom-error-response
  {:status 403
   :headers {"Content-Type" "text/html"}
   :body "<h1>Missing anti-forgery token</h1>"})

(def app
  (-> handler
      (wrap-anti-forgery {:error-response custom-error-response})
      (wrap-session)))
```

Or, for more control, an error handler can be supplied:

```clojure
(defn custom-error-handler [request]
  {:status 403
   :headers {"Content-Type" "text/html"}
   :body "<h1>Missing anti-forgery token</h1>"})

(def app
  (-> handler
      (wrap-anti-forgery {:error-handler custom-error-handler})
      (wrap-session)))
```



## Caveats

This middleware will prevent all HTTP methods except for GET and HEAD
from accessing your handler without a valid anti-forgery token.

You should therefore only apply this middleware to the parts of your
application designed to be accessed through a web browser. This
middleware should not be applied to handlers that define web services.

## License

Copyright © 2017 James Reeves

Distributed under the MIT License, the same as Ring.
