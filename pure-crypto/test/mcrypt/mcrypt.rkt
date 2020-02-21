#lang racket

(require file/sha1)
(require racket/file)

(provide (contract-out
          [mcrypt (-> string? string? string? string? string?)]
          ))

(define (mcrypt algorithm operation_mode data key)
  (let ([hex_data data]
        [hex_key key]
        [data_file #f]
        [key_file #f]
        [enc_file #f])

    (dynamic-wind
        (lambda ()
          (set! key_file (make-temporary-file "mcrypt~a" #f "."))
          (set! data_file (make-temporary-file "mcrypt~a" #f "."))
          (set! enc_file (string-append (path->string data_file) ".nc"))
          )
        (lambda ()
          (with-output-to-file data_file #:exists 'replace (lambda () (write-bytes (string->bytes/utf-8 data))))
          (with-output-to-file key_file #:exists 'replace (lambda () (write-bytes (string->bytes/utf-8 key))))
          (printf "data:[~a] key:[~a] operation_mode:[~a] algorithm:[~a]\n" data key operation_mode algorithm)
          (system (format "mcrypt -a ~a -m ~a --noiv -o hex -b -f ~a ~a " algorithm operation_mode key_file data_file))
          (string-upcase (bytes->hex-string (file->bytes enc_file))))
        (lambda ()
          (delete-file data_file)
          (delete-file key_file)
;          (delete-file enc_file)
          ))))
