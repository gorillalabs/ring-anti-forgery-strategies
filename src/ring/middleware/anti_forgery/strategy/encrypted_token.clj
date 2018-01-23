(ns ring.middleware.anti-forgery.strategy.encrypted-token
  (:require [ring.middleware.anti-forgery.strategy :as strategy]
            [clj-time.core :as time]
            [clj-time.coerce]
            [buddy.sign.jwt :as jwt]
            [buddy.core.hash :as hash]
            [crypto.equality :as crypto]
            [crypto.random]
            [clojure.tools.logging :as log])
  (:import (clojure.lang ExceptionInfo)))

(def ^:private crypt-options {:alg :dir :enc :a128cbc-hs256})

(defn sha256 [secret]
  (hash/sha256 secret))

(deftype EncryptedTokenSMS [secret expiration-period get-subject-fn]
  strategy/StateManagementStrategy

  (token [_ request]
    (delay (jwt/encrypt {:sub (get-subject-fn request)
                  :jti (crypto.random/base64 512)           ;; the nonce is to secure encryption (i.e. to prevent replay attacks). Used as JWT ID in the JWT (see https://tools.ietf.org/html/rfc7519#section-4.1.7).
                  :iat (clj-time.coerce/to-epoch (time/now)) ;; Issued at (see https://tools.ietf.org/html/rfc7519#section-4.1.6)
                  :exp (clj-time.coerce/to-epoch (time/plus (time/now) expiration-period)) ;; Expires (see https://tools.ietf.org/html/rfc7519#section-4.1.4)
}
                 secret
                 crypt-options)))

  (valid-token? [_ request read-token]
    (when-let [token (read-token request)]
      (try
        (let [{:keys [sub]} (jwt/decrypt token
                                         secret
                                         crypt-options)]

          ;; check subject (must either be empty (now, not at token claim) or equal to the one in the claims)
          (when-let [subject (get-subject-fn request)]
            (when-not (crypto/eq? sub subject)
              (throw (ex-info (str "Subject does not match " sub)
                              {:type :validation :cause :sub}))))

          true)
        (catch ExceptionInfo e
          (when-not (= (:type (ex-data e)) :validation)
            (throw e))
          (when-not (= (:cause (ex-data e)) :exp)
            (log/warn
             e
             "Security warning: Potential CSRF-Attack"
             (ex-data e)))
          false))))

  (write-token [_ response _ _]
    response))
