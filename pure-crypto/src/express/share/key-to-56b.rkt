#lang racket

(require "express-lib.rkt")

(provide (contract-out
          [write-report-key-to-56b (-> string? (listof natural?) (listof string?) (listof string?) path-string? void?)]
          ))

(define (write-report-key-to-56b key pc1_list key_b4_list key_56b_list express_path)
  (let* ([scrbl_dir (build-path express_path "key-to-56b")]
         [file_name (format "key-to-56b-~a.scrbl" key)]
         [scrbl_file (build-path scrbl_dir file_name)])

    (with-output-to-file
        (build-path express_path "report.scrbl") #:exists 'append
        (lambda ()
          (printf "@include-section[\"key-to-56b/~a\"]\n\n" file_name)))

    (make-directory* scrbl_dir)

    (with-output-to-file
        scrbl_file
      (lambda ()
        (printf "#lang scribble/base\n\n")
        (printf "@title{Map key to 56 Bits key[~a]}\n\n" key)
        (printf "The 64-bit key is permuted according to the pc1 table.\n\n")
        (printf "@section{PC1 Table[~a]}\n" key)
        (printf (display-list pc1_list 3 7))
        (printf "@section{Key 8BITS List[~a]}\n" key)
        (printf (display-list key_b4_list 10))
        (printf "@section{Mapped Key 7BITS List[~a]}\n" key)
        (printf (display-list key_56b_list 10))
        ))))

