#lang racket

(require file/sha1)
(require racket/file)

(provide (contract-out
          [openssl (-> (or/c 'plain 'hex) string? string? string? string?)]
          ))

(define (openssl data_format cmd data key)
  (let ([hex_data data]
        [hex_key key]
        [data_file #f]
        [enc_file #f])

    (when (eq? data_format 'plain)
          (set! hex_data (bytes->hex-string (string->bytes/utf-8 data)))
          (set! hex_key (bytes->hex-string (string->bytes/utf-8 key))))

    (dynamic-wind
        (lambda ()
          (set! enc_file (make-temporary-file "openssl~a" #f "."))
          (set! data_file (make-temporary-file "openssl~a" #f ".")))
        (lambda ()
          (with-output-to-file data_file #:exists 'replace (lambda () (write-bytes (hex-string->bytes hex_data))))
          (printf "cmd:[~a] data:[~a] key:[~a]\n" cmd data key)
          (system (format "openssl ~a -in ~a -out ~a -K ~a" cmd data_file enc_file hex_key))
          (string-upcase (bytes->hex-string (file->bytes enc_file))))
        (lambda ()
          (delete-file data_file)
          (delete-file enc_file)))))
