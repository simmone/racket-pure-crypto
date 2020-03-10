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

    (check-equal?
     (decrypt #:cipher? 'aes #:operation_mode? 'ecb #:data_format? 'hex #:key_format? 'hex
              (string-append
               "3AD77BB40D7A3660A89ECAF32466EF97"
               "F5D3D58503B9699DE785895A96FDBAAF"
               "43B1CD7F598ECE23881B00E3ED030688"
               "7B0C785E27E8AD3F8223207104725DD4")
              "2b7e151628aed2a6abf7158809cf4f3c")
     (string-append
      "6BC1BEE22E409F96E93D7E117393172A"
      "AE2D8A571E03AC9C9EB76FAC45AF8E51"
      "30C81C46A35CE411E5FBC1191A0A52EF"
      "F69F2445DF4F9B17AD2B417BE66C3710"))
    )

   (test-case
    "test-ecb-192"

    (check-equal?
     (decrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ecb
              "C326C015F55309BCD0A6219107969FF0"
              "133457799BBCDFF133457799BBCDFFAB0123456789ABCDEF")
     "0123456789ABCDEF0123456789ABCDEF")

    (check-equal?
     (decrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ecb
              (string-append
               "BD334F1D6E45F25FF712A214571FA5CC"
               "974104846D0AD3AD7734ECB3ECEE4EEF"
               "EF7AFD2270E2E60ADCE0BA2FACE6444E"
               "9A4B41BA738D6C72FB16691603C18E0E")
              "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
     (string-append
      "6BC1BEE22E409F96E93D7E117393172A"
      "AE2D8A571E03AC9C9EB76FAC45AF8E51"
      "30C81C46A35CE411E5FBC1191A0A52EF"
      "F69F2445DF4F9B17AD2B417BE66C3710"))

    (check-equal?
     (decrypt #:cipher? 'aes #:operation_mode? 'ecb
              "4925EA049EB1129593CDA1C980EBFD41"
              "chensihehesichenxiaochen")
     "chenxiaoxiaochen")

    (check-equal?
     (decrypt #:cipher? 'aes #:operation_mode? 'ecb
              "1A5DF9AB8B6D5278A3859029FBD7305D"
              "chensihehesichenxiaochen")
     "a")

    )

   ))

(run-tests test-aes)
