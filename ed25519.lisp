;;;; ed25519.lisp

(in-package #:ed25519)
(declaim (optimize (speed 3)))

;;; "ed25519" goes here. Hacks and glory await!


(eval-when (:compile-toplevel :load-toplevel :execute)
  (defconstant +b+ 256)
  (defconstant +q+ (- (expt 2 255) 19))
  (defconstant +l+ (+ (expt 2 252) 27742317777372353535851937790883648493))
  
  (defun ensure-vub8 (m)
    (if (equal (array-element-type m)
	       (upgraded-array-element-type '(unsigned-byte 8)))
	m
	(make-array (length m) :element-type '(unsigned-byte 8)
		       :initial-contents m)))

  (defun h (m)
    (let ((m (ensure-vub8 m)))
    (ironclad:digest-sequence :sha512 m)))

  (defun expmod (b e m)
    (if (zerop e)
	1
	(let ((tee (mod (expt (expmod b (floor e 2) m) 2) m)))
	  (if (oddp e)
	      (mod (* tee b) m)
	      tee))))

  (defun inv (x)
    (expmod x (- +q+ 2) +q+))

  (defconstant +d+ (* -121665 (inv 121666)))
  (defconstant +i+ (expmod 2 (floor (1- +q+) 4) +q+))

  (defun xrecover (y)
    (let* ((xx (* (1- (* y y)) (inv (1+ (* +d+ y y)))))
	   (x (expmod xx (floor (+ +q+ 3) 8) +q+)))
      (unless (zerop (mod (- (* x x) xx) +q+))
	(setf x (mod (* x +i+) +q+)))
      (when (oddp x) (setf x (- +q+ x)))
      x))
  
  (defconstant +by+ (* 4 (inv 5)))
  (defconstant +bx+ (xrecover +by+))
  (defparameter *b* (list (mod +bx+ +q+)
			  (mod +by+ +q+))))

(defun edwards (p q)
  (destructuring-bind (x1 y1) p
    (destructuring-bind (x2 y2) q
      (list
       (mod
	(* (+ (* x1 y2) (* x2 y1))
	   (inv (+ 1 (* +d+ x1 x2 y1 y2))))
	+q+)
       (mod
	(* (+ (* y1 y2) (* x1 x2))
	   (inv (- 1 (* +d+ x1 x2 y1 y2))))
	+q+)))))

(defun scalarmult (p e)
  (if (zerop e) (list 0 1)
      (let* ((q (scalarmult p (floor e 2)))
	     (q (edwards q q)))
	(if (oddp e) (edwards q p) q))))

(defun encodeint (y)
  (loop with result = (make-array (floor +b+ 8) :element-type '(unsigned-byte 8))
     for i from 0 below (floor +b+ 8)
     do (setf (aref result i) (ldb (byte 8 (* i 8)) y))
     finally (return result)))

(defun encodepoint (p)
  (encodeint (logior (ash (logand (first p) 1)
			  (1- +b+))
                     (ldb (byte (1- +b+) 0) (second p)))))

(defun xbit (h i)
 (ldb (byte 1 (mod i 8)) (aref h (floor i 8))))

(defun publickey (sk)
  (let*
      ((h (h sk))
       (a (+ (expt 2 (- +b+ 2)) (loop for i from 3 below (- +b+ 2)
				 sum (* (expt 2 i) (xbit h i)))))
       (a (scalarmult *b* a)))
    (encodepoint a)))

(defun hint (m)
  (let ((h (h m)))
    (loop with result = 0
       for i from 0 below (floor +b+ 4)
       do (setf (ldb (byte 8 (* i 8)) result) (aref h i))
       finally (return result))))

(defun signature (m sk pk)
  (let* ((h (h sk))
	 (a (+
	     (expt 2 (- +b+ 2))
	     (loop for i from 3 below (- +b+ 2)
		sum (* (expt 2 i) (xbit h i)))))
	 (r (hint (concatenate 'vector
			       (subseq h (floor +b+ 8) (floor +b+ 4))
			       m)))
	 (rr (scalarmult *b* r))
	 (s (mod (+ r (*
		       (hint (concatenate 'vector (encodepoint rr) pk m))
		       a))
		 +l+)))
    ;(format t "~&a: ~S~%r: ~S~%R: ~S~%s: ~S~%hint: ~S~%"
;a r rr s (hint (concatenate 'vector (encodepoint rr) pk m)))
    ;(print (list a r rr s))
    ;(print (list pk m))
    (concatenate 'vector (encodepoint rr) (encodeint s))))

(defun isoncurve (p)
  (destructuring-bind (x y) p
    (zerop
     (mod
      (+
       (* x x -1)
       (* y y)
       -1
       (* -1 +d+ x x y y))
      +q+))))

(defun decodeint (s)
 (loop with result = 0
    for i from 0 below (floor +b+ 8)
      do (setf (ldb (byte 8 (* i 8)) result) (aref s i))
      finally (return result)))


(defun decodepoint (s)
  (let* ((y (loop for i from 0 below (1- +b+)
	       sum (* (expt 2 i) (xbit s i))))
	 (x (xrecover y)))
    (when (/= (logand x 1) (xbit s (1- +b+)))
      (setf x (- +q+ x)))
    (let ((p (list x y)))
      (unless (isoncurve p) (error "Decoding point that is not on curve"))
      p)))

(defun checkvalid (s m pk)
  (when (/= (length s) (floor +b+ 4))
    (error "signature lingth is wrong"))
  (when (/= (length pk) (floor +b+ 8))
    (error "publick-key length is wrong"))
  (let*
      ((r (decodepoint (subseq s 0 (floor +b+ 8))))
       (a (decodepoint pk))
       (s (decodeint (subseq s (floor +b+ 8) (floor +b+ 4))))
       (h (hint (concatenate 'vector (encodepoint r) pk m))))
    ;(print (list r a s h))
    (unless (equal (scalarmult *b* s)
		 (edwards r (scalarmult a h)))
      (error "Signature fails verification")))
  t)

