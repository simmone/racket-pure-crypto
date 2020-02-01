#lang racket

(provide (contract-out
          [write-report-header (-> string? path-string? void?)]
          ))

(define (write-report-header title express_path)
  (let* ([scrbl_file (build-path express_path "report.scrbl")])

    (make-directory* express_path)

    (with-output-to-file
        scrbl_file
      (lambda ()
        (printf "#lang scribble/manual\n\n")
        (printf "@title{~a Report}\n\n" title)
        (printf "report the process of encrption.\n\n")
        (printf "@table-of-contents[]\n\n")
        ))))

