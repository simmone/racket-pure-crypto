#lang racket

(require "src/encrypt.rkt")
(require "src/decrypt.rkt")

(provide (contract-out
          [encrypt (->* (string? string?)
                    (
                     #:cipher? (or/c 'des 'tdes 'aes)
                     #:key_format? (or/c 'hex 'base64 'utf-8)
                     #:data_format? (or/c 'hex 'base64 'utf-8)
                     #:encrypted_format? (or/c 'hex 'base64)
                     #:padding_mode? (or/c 'pkcs7 'zero 'no-padding 'ansix923 'iso10126)
                     #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb 'ctr)
                     #:iv? (or/c #f string?)
                     #:detail? (or/c #f (listof (or/c 'raw 'console path-string?)))
                    )
                    (or/c #f string?))]
          [decrypt (->* (string? string?)
                      (
                       #:cipher? (or/c 'des 'tdes 'aes)
                       #:key_format? (or/c 'hex 'base64 'utf-8)
                       #:data_format? (or/c 'hex 'base64 'utf-8)
                       #:encrypted_format? (or/c 'hex 'base64)
                       #:padding_mode? (or/c 'pkcs7 'zero 'no-padding 'ansix923 'iso10126)
                       #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb 'ctr)
                       #:iv? string?
                       #:detail? (or/c #f (listof (or/c 'raw 'console path-string?)))
                      )
                      (or/c #f string?))]
          ))
