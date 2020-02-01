#lang racket

(require "express-lib.rkt")

(provide (contract-out
          [write-report-cd0-cd16 (-> string? (listof natural?) string? string? (listof string?) (listof string?) path-string? void?)]
          ))

(define (write-report-cd0-cd16 key length_list c0 d0 c_list d_list express_path)
  (let* ([scrbl_dir (build-path express_path "cd0-cd16")]
         [file_name (format "cd0-cd16-~a.scrbl" key)]
         [scrbl_file (build-path scrbl_dir file_name)])

    (with-output-to-file
        (build-path express_path "report.scrbl") #:exists 'append
        (lambda ()
          (printf "@include-section[\"cd0-cd16/~a\"]\n\n" file_name)))

    (make-directory* scrbl_dir)

    (with-output-to-file
        scrbl_file
      (lambda ()
        (printf "#lang scribble/base\n\n")
        (printf "@title{Shift C0/D0 to C16/D16[~a]}\n\n" key)
        (printf "C0 is left half of 56bits key, D0 is the right half. Recurrsive shift left the key by shift length list\n\n")
        (printf "@section{C0[~a]}\n\n" key)
        (printf "[~a]\n\n" c0)
        (printf "@section{D0[~a]}\n\n" key)
        (printf "[~a]\n\n" d0)
        (printf "@section{Shift Lengh List[~a]}\n" key)
        (printf (display-list length_list 3 1))
        (printf "@section{C1-C16[~a]}\n" key)
        (printf (display-list c_list 58 1))
        (printf "@section{D1-D1f6[~a]}\n" key)
        (printf (display-list d_list 58 1))
        ))))

