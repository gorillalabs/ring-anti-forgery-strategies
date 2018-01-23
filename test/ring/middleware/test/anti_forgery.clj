(ns ring.middleware.test.anti-forgery
  (:require [ring.middleware.anti-forgery :as af :refer :all]
            [ring.middleware.anti-forgery.strategy.encrypted-token :as encrypted-token]
            [ring.middleware.anti-forgery.strategy.signed-token :as signed-token]
            [buddy.core.keys :as keys]
            [clj-time.core :as time]
            [ring.middleware.anti-forgery.strategy :as strategy]
            [ring.middleware.anti-forgery.strategy.session :as session]
            [ring.mock.request :refer [request]]
            [clojure.test :refer :all]))

(def ^:private expires-in-one-hour (time/hours 1))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Things necessary to test signed-token-strategy
;;

(def ^:private pubkey (keys/public-key "dev-resources/test-certs/pubkey.pem"))
(def ^:private privkey (keys/private-key "dev-resources/test-certs/privkey.pem" "antiforgery"))
(def ^:private other-private-key (keys/private-key "dev-resources/test-certs/privkey-other.pem" "other"))

(def ^:private signed-token-sms (signed-token/->SignedTokenSMS pubkey privkey expires-in-one-hour :identity))

(def ^:private signed-token-options {:state-management-strategy signed-token-sms})

(defn create-signed-csrf-token
  ([privkey expiration]
   (force (strategy/token (signed-token/->SignedTokenSMS nil privkey expiration :identity) nil)))
  ([privkey expiration subject]
   (force (strategy/token (signed-token/->SignedTokenSMS nil privkey expiration :identity) {:identity subject}))))

(defn- valid-signed-token? [public-key token]
  (strategy/valid-token?
    (signed-token/->SignedTokenSMS public-key nil nil :identity)
    token
    identity))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Things necessary to test encrypted-token-strategy
;;

(def ^:private secret "secret-to-validate-token-after-decryption-to-make-sure-i-encrypted-stuff")

(def ^:private encrypted-token-sms (encrypted-token/->EncryptedTokenSMS
                                     (encrypted-token/sha256 secret)
                                     expires-in-one-hour :identity))

(def ^:private encrypted-token-options {:state-management-strategy encrypted-token-sms})

(defn create-encrypted-csrf-token
  ([secret expiration]
   (force (strategy/token (encrypted-token/->EncryptedTokenSMS (encrypted-token/sha256 secret) expiration :identity) nil)))
  ([secret expiration subject]
   (force (strategy/token (encrypted-token/->EncryptedTokenSMS (encrypted-token/sha256 secret) expiration :identity) {:identity subject}))))

(defn- valid-encrypted-token? [secret token]
  (strategy/valid-token?
    (encrypted-token/->EncryptedTokenSMS (encrypted-token/sha256 secret) nil :identity)
    token
    identity))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Generic helpers
;;

(defn- status=* [handler status req]
  (= status (:status (handler req))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Tests follow below
;;


(deftest forgery-protection-via-signed-token-test
  (let [expired-one-hour-ago (time/hours -1)
        response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response) signed-token-options)
        status= (partial status=* handler)]

    (testing "without anti-forgery-token"
      (are [status req] (status= status req)
                        403 (request :post "/")
                        403 (-> (request :post "/")
                                (assoc :identity "user-id"))))

    (testing "with ill-formated anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                ;; anti-forgery-token not decryptable with our key
                                (assoc :form-params {"__anti-forgery-token" "bar"}))))

    (testing "with non-decryptable anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                ;; anti-forgery-token not decryptable with our key
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token other-private-key expired-one-hour-ago)}))))
    (testing "with expired anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expired-one-hour-ago)}))))
    (testing "with anti-forgery-token for wrong subject"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expires-in-one-hour "user-id")})
                                (assoc :identity "another-user-id"))))
    (testing "with anti-forgery-token for no subject"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expires-in-one-hour)})
                                (assoc :identity "user-id"))))

    (testing "with correct anti-forgery-token if no subject is given.
    (Attention: Has different nounce, but that's ok)"
      (are [status req] (status= status req)
                        200 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expires-in-one-hour)}))))

    (testing "with correct anti-forgery-token if subject is given.
    (Attention: Has different nounce, but that's ok)"
      (are [status req] (status= status req)
                        200 (-> (request :post "/")
                                (assoc :identity "user-id")
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expires-in-one-hour "user-id")}))))))

(deftest forgery-protection-via-encrypted-token-test
  (let [expired-one-hour-ago (time/hours -1)
        response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response) encrypted-token-options)
        status= (partial status=* handler)]

    (testing "without anti-forgery-token"
      (are [status req] (status= status req)
                        403 (request :post "/")
                        403 (-> (request :post "/")
                                (assoc :identity "user-id"))))

    (testing "with ill-formated anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" "bar"}))))

    (testing "with non-decryptable anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                ;; anti-forgery-token not decryptable with our key
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token "another-secret" expired-one-hour-ago)}))))

    (testing "with expired anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token secret expired-one-hour-ago)}))))
    (testing "with anti-forgery-token for wrong subject"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token secret expires-in-one-hour "user-id")})
                                (assoc :identity "another-user-id"))))
    (testing "with anti-forgery-token for no subject"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token secret expires-in-one-hour)})
                                (assoc :identity "user-id"))))

    (testing "with correct anti-forgery-token if no subject is given.
    (Attention: Has different nounce, but that's ok)"
      (are [status req] (status= status req)
                        200 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token secret expires-in-one-hour)}))))

    (testing "with correct anti-forgery-token if subject is given.
    (Attention: Has different nounce, but that's ok)"
      (are [status req] (status= status req)
                        200 (-> (request :post "/")
                                (assoc :identity "user-id")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token secret expires-in-one-hour "user-id")}))))))

(deftest request-method-via-signed-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response) signed-token-options)]
    (are [status req] (= (:status (handler req)) status)
                      200 (request :head "/")
                      200 (request :get "/")
                      200 (request :options "/")
                      403 (request :post "/")
                      403 (request :put "/")
                      403 (request :patch "/")
                      403 (request :delete "/"))))

(deftest request-method-via-encrypted-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response) encrypted-token-options)]
    (are [status req] (= (:status (handler req)) status)
                      200 (request :head "/")
                      200 (request :get "/")
                      200 (request :options "/")
                      403 (request :post "/")
                      403 (request :put "/")
                      403 (request :patch "/")
                      403 (request :delete "/"))))

(deftest token-binding-via-signed-token-test
  (letfn [(handler [request]
            {:status  200
             :headers {}
             :body    @*anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler signed-token-options) (request :get "/"))]
      (is (valid-signed-token? pubkey (:body response))))))

(deftest token-binding-via-encrypted-token-test
  (letfn [(handler [request]
            {:status  200
             :headers {}
             :body    @*anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler encrypted-token-options) (request :get "/"))]
      (is (< (count (:body response)) 3000))
      (is (valid-encrypted-token? secret (:body response))))))

(deftest no-session-response-via-signed-token-test
  (let [response {:status 200 :headers {} :session {"foo" "bar"} :body nil}
        handler (wrap-anti-forgery (constantly response) signed-token-options)
        session (:session (handler (request :get "/")))]
    (is (not (contains? session ::af/anti-forgery-token)))
    (is (= (session "foo") "bar"))))

(deftest forgery-protection-cps-via-signed-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (fn [_ respond _] (respond response)) signed-token-options)]

    (testing "missing token"
      (let [req (-> (request :post "/")
                    (assoc :form-params {"__anti-forgery-token" "foo"}))
            resp (promise)
            ex (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 403))))

    (testing "valid token"
      (let [req (-> (request :post "/")
                    (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expires-in-one-hour)}))
            resp (promise)
            ex (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 200))))))
