(defproject gorillalabs/ring-anti-forgery-strategies "0.0.0"
            :description "Ring middleware to prevent CSRF attacks"
            :url "https://github.com/gorillalabs/ring-anti-forgery-strategies"
            :license {:name "The MIT License"
                      :url  "http://opensource.org/licenses/MIT"}
            :middleware [leiningen.v/dependency-version-from-scm
                         leiningen.v/version-from-scm
                         leiningen.v/add-workspace-data]
            :plugins [[com.roomkey/lein-v "6.2.0"]]
            :dependencies [[org.clojure/clojure "1.8.0"]
                           [ring/ring-anti-forgery "1.2.0"]
                           [org.clojure/tools.logging "0.4.0"]
                           [crypto-random "1.2.0"]
                           [crypto-equality "1.0.0"]
                           [hiccup "1.0.5"]
                           [clj-time "0.14.2"]
                           [buddy/buddy-core "1.4.0"]
                           [buddy/buddy-sign "2.2.0"]]
            :aliases {"test-all" ["with-profile" "default:+1.7:+1.8:+1.9" "test"]}
            :profiles
            {:dev {:dependencies [[ring/ring-mock "0.3.0"]]}
             :1.7 {:dependencies [[org.clojure/clojure "1.7.0"]]}
             :1.8 {:dependencies [[org.clojure/clojure "1.8.0"]]}
             :1.9 {:dependencies [[org.clojure/clojure "1.9.0"]]}}
            :vcs :git
            :scm {:name "git"
                  :url  "https://github.com/gorillalabs/ring-anti-forgery-strategies"}

            :deploy-repositories [["releases" :clojars]]
            :release-tasks [["vcs" "assert-committed"]
                            ["v" "update"]                  ;; compute new version & tag it
                            ["deploy"]
                            ["vcs" "push"]])
