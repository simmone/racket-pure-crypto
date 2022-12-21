#lang racket

(require file/sha1)
(require net/base64)

(provide (contract-out
          [des (->
                (and/c string? #px"^([0-1]){64}$")
                (listof (and/c string? #px"^([0-1]){48}$"))
                (and/c string? #px"^([0-1]){64}$"))
               ]
          [undes (->
                  (and/c string? #px"^([0-1]){64}$")
                  (listof (and/c string? #px"^([0-1]){48}$"))
                  (and/c string? #px"^([0-1]){64}$"))
                 ]
          ))

(require "../../lib/constants.rkt")
(require "../../lib/lib.rkt")

(define (des operated_binary_data key_list)
  (let* ([m0 operated_binary_data]
         [ip0 (transform-binary-string m0 *ip_table*)]
         [l0 (substring ip0 0 32)]
         [r0 (substring ip0 32)]
         [encrypted_block_binary_data #f])

    (let loop-encode ([ln_1 l0]
                      [rn_1 r0]
                      [n 1])
      (if (<= n 16)
          (let ([en #f]
                [kn #f]
                [kn_xor_en #f]
                [sbn #f]
                [fn #f]
                [rn #f])

            (set! en (transform-binary-string rn_1 *e_table*))

            (set! kn (list-ref key_list (sub1 n)))

            (set! kn_xor_en
                  (~r #:base 2 #:min-width 48 #:pad-string "0"
                      (bitwise-xor (string->number kn 2) (string->number en 2))))

            (set! sbn
                  (let loop-sb ([loop_list (split-string kn_xor_en 6)]
                                [index 1]
                                [result_str ""])
                    (if (not (null? loop_list))
                        (loop-sb (cdr loop_list) (add1 index) (string-append result_str (b6->b4 index (car loop_list))))
                        result_str)))

            (set! fn (transform-binary-string sbn *p_table*))

            (set! rn
                  (~r #:base 2 #:min-width 32 #:pad-string "0"
                      (bitwise-xor (string->number ln_1 2) (string->number fn 2))))

            (loop-encode rn_1 rn (add1 n)))
          (let* ([r16l16 (string-append rn_1 ln_1)]
                 [ip1 (transform-binary-string r16l16 *ip_1_table*)])
            ip1)))))

(define (undes binary_data k_list)
  (let ([ip1 #f]
        [l16 #f]
        [r16 #f])
    (set! ip1 (transform-binary-string binary_data *reverse_ip_1_table*))
    
    (set! l16 (substring ip1 32))

    (set! r16 (substring ip1 0 32))

    (let loop ([rn_1 l16]
               [rn r16]
               [n 16])
      (if (>= n 1)
          (let* ([en #f]
                 [kn #f]
                 [kn_xor_en #f]
                 [sbn #f]
                 [fn #f]
                 [ln_1 #f])

            (set! en (transform-binary-string rn_1 *e_table*))

            (set! kn (list-ref k_list (sub1 n)))

            (set! kn_xor_en
                  (~r #:base 2 #:min-width 48 #:pad-string "0"
                      (bitwise-xor (string->number kn 2) (string->number en 2))))

            (set! sbn
                  (let loop-sb ([loop_list (split-string kn_xor_en 6)]
                                [index 1]
                                [result_str ""])
                    (if (not (null? loop_list))
                        (loop-sb (cdr loop_list) (add1 index) (string-append result_str (b6->b4 index (car loop_list))))
                        result_str)))
            (set! fn (transform-binary-string sbn *p_table*))

            (set! ln_1
                  (~r #:base 2 #:min-width 32 #:pad-string "0"
                      (bitwise-xor (string->number rn 2) (string->number fn 2))))

            (loop
             ln_1
             rn_1
             (sub1 n)))
          (let ([l0r0 #f]
                [binary_data #f])
            (set! l0r0 (string-append rn_1 rn))
            
            (set! binary_data (transform-binary-string l0r0 *reverse_ip_table*))

            binary_data)))))

