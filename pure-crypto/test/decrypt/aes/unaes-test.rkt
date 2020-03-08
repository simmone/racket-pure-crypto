#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../../src/decrypt.rkt")

(define test-aes
  (test-suite
   "test-aes"

   (test-case
    "test-ecb-128"

    (check-equal?
     (decrypt #:cipher? 'aes
              "4AE08C70BEA1D25577F34EF92877F787"
              "133457799BBCDFF133457799BBCDFFAB"
              #:operation_mode? 'ecb #:data_format? 'hex #:key_format? 'hex)
     "0123456789ABCDEF0123456789ABCDEF")
    )

    (check-equal?
     (decrypt #:cipher? 'aes #:operation_mode? 'ecb #:data_format? 'hex #:key_format? 'hex
              (string-append
               "3AD77BB40D7A3660A89ECAF32466EF97"
               "F5D3D58503B9699DE785895A96FDBAAF"
               "43B1CD7F598ECE23881B00E3ED030688"
               "7B0C785E27E8AD3F8223207104725DD4")
              "2b7e151628aed2a6abf7158809cf4f3c")
     (string-append
      "6bc1bee22e409f96e93d7e117393172a"
      "ae2d8a571e03ac9c9eb76fac45af8e51"
      "30c81c46a35ce411e5fbc1191a0a52ef"
      "f69f2445df4f9b17ad2b417be66c3710")
     )

   ))

(run-tests test-aes)
