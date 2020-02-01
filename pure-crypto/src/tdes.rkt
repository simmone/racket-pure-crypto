#lang racket

(require file/sha1)
(require net/base64)

(require "des.rkt")
(require "undes.rkt")

(provide (contract-out
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
          ))

(require "lib/constants.rkt")
(require "lib/lib.rkt")
(require "lib/padding.rkt")
(require "express/express.rkt")
(require "share.rkt")

(define (tdes data key
             #:key_format? [key_format? 'utf-8]
             #:data_format? [data_format? 'utf-8]
             #:encrypted_format? [encrypted_format? 'hex]
             #:padding_mode? [padding_mode? 'pkcs5]
             #:operation_mode? [operation_mode? 'cbc]
             #:iv? [iv? "0000000000000000"]
             #:express? [express? #f]
             #:express_path? [express_path? ".des.express"]
             )

  (des data key
       #:type? 'tdes
       #:key_format? key_format?
       #:data_format? data_format?
       #:encrypted_format? encrypted_format?
       #:padding_mode? padding_mode?
       #:operation_mode? operation_mode?
       #:iv? iv?
       #:express? express?
       #:express_path? express_path?))

