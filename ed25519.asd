;;;; ed25519.asd

(asdf:defsystem #:ed25519
  :description "Implementation of ed25519 signature algorithm"
  :author "Jason Miller <aidenn0@geocities.com>"
  :license "MIT/X11"
  :depends-on (#:ironclad)
  :serial t
  :components ((:file "package")
               (:file "ed25519")))

