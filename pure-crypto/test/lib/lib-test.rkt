#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../src/lib/lib.rkt")
(require "../../src/lib/constants.rkt")

(define test-lib
  (test-suite
   "test-lib"

   (test-case
    "test-hex-string->binary-string-list"

    (check-equal? 
     (hex-string->binary-string-list "133457799BBCDFF1" 4)
     '("0001" "0011" "0011" "0100" "0101" "0111" "0111" "1001" "1001" "1011" "1011" "1100" "1101" "1111" "1111" "0001"))

    (check-equal? 
     (hex-string->binary-string-list "133457799BBCDFF1" 8)
     '("00010011" "00110100" "01010111" "01111001" "10011011" "10111100" "11011111" "11110001"))
    )

   (test-case
    "test-hex-string->binary-string"

    (check-equal? 
     (hex-string->binary-string "133457799BBCDFF1")
     "0001001100110100010101110111100110011011101111001101111111110001")
    )

   (test-case
    "test-reverse-table"

    (printf "~a\n" (reverse-table *ip_table*))

    (printf "~a\n" (reverse-table *ip_1_table*))
    
    (check-equal?
     (reverse-table
      '(2 3 4 1))
     '(4 1 2 3))

    (check-equal?
     (reverse-table
      '(2 3 3 4 5 5 1))
     '(7 1 3 4 6))
    )

   (test-case
    "test-transform-binary-string"

    (check-equal? 
     (transform-binary-string
      "0001001100110100010101110111100110011011101111001101111111110001"
      *pc1_table*)
     "11110000110011001010101011110101010101100110011110001111")

    (check-equal? 
     (transform-binary-string
      "1001100100111010101001100010111101111111100111011000111111101100"
      *ip_1_table*)
     "1110100110011101101011111111101111110000100101111000001001101110")

    )

   (test-case
    "test-split-string"

    (check-equal? 
     (split-string "1234567876543210" 4)
     '("1234" "5678" "7654" "3210"))

    (check-equal? 
     (split-string "1234567876543210" 8)
     '("12345678" "76543210"))

    (check-equal? 
     (split-string "12345678765432101" 8)
     '("12345678" "76543210" "1"))
    )

   (test-case
    "test-bitwise-shift-left"

    (check-equal? 
     (shift-left "11110000110011001010210101111" 1)
     "11100001100110010102101011111")

    (check-equal? 
     (shift-left "11000011001100101021010111111" 2)
                 "00001100110010102101011111111")

    )
   
   (test-case
    "test-b6->b4"
    
    (check-equal? (b6->b4 1 "011011") "0101")
    (check-equal? (b6->b4 2 "010001") "1100")
    (check-equal? (b6->b4 3 "011110") "1000")
    (check-equal? (b6->b4 4 "111010") "0010")
    (check-equal? (b6->b4 5 "100001") "1011")
    (check-equal? (b6->b4 6 "100110") "0101")
    (check-equal? (b6->b4 7 "010100") "1001")
    (check-equal? (b6->b4 8 "100111") "0111")

    )

   ))

(run-tests test-lib)
