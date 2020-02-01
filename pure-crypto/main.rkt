#lang racket

(require "src/des.rkt")
(require "src/undes.rkt")
(require "src/tdes.rkt")
(require "src/untdes.rkt")

(provide (contract-out
          [des (->* (string? string?)
                    (
                     #:key_format? (or/c 'hex 'base64 'utf-8)
                     #:data_format? (or/c 'hex 'base64 'utf-8)
                     #:encrypted_format? (or/c 'hex 'base64)
                     #:padding_mode? (or/c 'pkcs5 'zero 'no-padding 'ansix923 'iso10126)
                     #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb)
                     #:iv? string?
                     #:express? boolean?
                     #:express_path? path-string?
                    )                               
                    string?)]
          [undes (->* (string? string?)
                    (
                     #:key_format? (or/c 'hex 'base64 'utf-8)
                     #:data_format? (or/c 'hex 'base64 'utf-8)
                     #:encrypted_format? (or/c 'hex 'base64)
                     #:padding_mode? (or/c 'pkcs5 'zero 'no-padding 'ansix923 'iso10126)
                     #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb)
                     #:iv? string?
                     #:express? boolean?
                     #:express_path? path-string?
                    )                               
                    string?)]
          [tdes (->* (string? string?)
                   (
                     #:key_format? (or/c 'hex 'base64 'utf-8)
                     #:data_format? (or/c 'hex 'base64 'utf-8)
                     #:encrypted_format? (or/c 'hex 'base64)
                     #:padding_mode? (or/c 'pkcs5 'zero 'no-padding 'ansix923 'iso10126)
                     #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb)
                     #:iv? string?
                     #:express? boolean?
                     #:express_path? path-string?
                    )                               
                    string?)]
          [untdes (->* (string? string?)
                   (
                     #:key_format? (or/c 'hex 'base64 'utf-8)
                     #:data_format? (or/c 'hex 'base64 'utf-8)
                     #:encrypted_format? (or/c 'hex 'base64)
                     #:padding_mode? (or/c 'pkcs5 'zero 'no-padding 'ansix923 'iso10126)
                     #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb)
                     #:iv? string?
                     #:express? boolean?
                     #:express_path? path-string?
                    )                               
                    string?)]
          ))
