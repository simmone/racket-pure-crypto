#lang racket

(require file/sha1)
(require net/base64)

(require "../../../../racket-detail/detail/main.rkt")

(require "../lib/constants.rkt")
(require "../lib/lib.rkt")

(provide (contract-out
          [to-hex-key (->*
                         (string?)
                         (
                          #:cipher? (or/c 'des 'tdes 'aes)
                          #:key_format? (or/c 'hex 'base64 'utf-8)
                         )
                         (and/c string? #px"^([0-9]|[a-f])+$"))]
          ))

(define (to-hex-key
         key
         #:cipher? [cipher? 'aes]
         #:key_format? [key_format? 'utf-8]
         )

  (detail-div
   #:font_size? 'small
   #:line_break_length? 100
   (lambda ()
     (let ([hex_key #f])
       (detail-h2 "Key To Hex Format")

       (detail-line (format "key:[~a][~a]" key key_format?))
       
       (set! hex_key
             (cond
              [(eq? key_format? 'utf-8)
               (bytes->hex-string (string->bytes/utf-8 key))]
              [(eq? key_format? 'base64)
               (bytes->hex-string (base64-decode (string->bytes/utf-8 key)))]
              [else
               (string-downcase key)]))

       (detail-line (format "key in hex:[~a]" hex_key))

       (cond
        [(or
          (eq? cipher? 'des)
          (eq? cipher? 'tdes))
         (when (and
                (not (= (string-length hex_key) 16))
                (not (= (string-length hex_key) 32))
                (not (= (string-length hex_key) 48)))
           (error (format "DES key length is invalid. expect 16/32/48(hex), but get ~a" (string-length hex_key))))]
        [else
         (when (and
                (not (= (string-length hex_key) 32))
                (not (= (string-length hex_key) 48))
                (not (= (string-length hex_key) 64))
                )
           (error (format "AES key length is invalid. expect 32/48/64(hex), but get ~a" (string-length hex_key))))])

       hex_key))))
