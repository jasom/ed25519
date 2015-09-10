(in-package #:ed25519)

(defun unhexlify (string)
  (make-array (/ (length string) 2)
	      :element-type '(unsigned-byte 8)
	      :initial-contents
	      (loop for i from 0 below (1- (length string)) by 2
		 collect (parse-integer (subseq string i (+ i 2)) :radix 16))))
   

(Defun hexlify (byte-vector)
  (with-output-to-string (s)
    (loop for item across byte-vector
	 do (format s "~2,'0X" item))))

(defun run-test ()
  (with-open-file (s (asdf:system-relative-pathname :ed25519 "sign.input"))
    (loop for line = (string-trim '(#\Newline #\Return) (read-line s))
       for x = (split-sequence:split-sequence #\: line)
       while (not (zerop (length line)))
       do
	 (let* ((sk (unhexlify (subseq (first x) 0 64)))
		(pk (publickey sk))
		(m (unhexlify (third x)))
		(s (signature m sk pk)))
	   (checkvalid s m pk)
	   (let ((forged-success nil))
	     (ignore-errors
	       (let ((forgedm
		      (if (zerop (length m))
			  #(#.(char-code #\x))
			  (concatenate
			   'vector
			   (loop for i from 0 to (length m)
			      if (= i (1- (length m)))
			      collect (1+ (aref m i))
			      else collect (aref m i))))))
		 (checkvalid s forgedm pk)
		 (setf forged-success t)))
	     (assert (not forged-success))
	     (assert (equalp (first x) (hexlify (concatenate 'vector sk pk))))
	     (assert (equalp (second x) (hexlify pk)))
	     (assert (equalp (fourth x) (hexlify (concatenate 'vector s m)))))))))
