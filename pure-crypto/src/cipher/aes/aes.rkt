#lang racket

(require detail)

(require "s-box.rkt")
(require "shift-rows.rkt")
(require "key-expansion.rkt")
(require "add-round-key.rkt")
(require "mix-columns.rkt")

(provide (contract-out
          [aes (->
                (and/c string? #px"^([0-9]|[a-f]){32}$")
                (and/c string?
                       (or/c #px"^([0-9]|[a-f]){32}$" #px"^([0-9]|[a-f]){48}$" #px"^([0-9]|[a-f]){64}$"))
                (and/c string? #px"^([0-9]|[a-f]){32}$"))]
          [unaes (->
                  (and/c string? #px"^([0-9]|[a-f]){32}$")
                  (and/c string?
                         (or/c #px"^([0-9]|[a-f]){32}$" #px"^([0-9]|[a-f]){48}$" #px"^([0-9]|[a-f]){64}$"))
                  (and/c string? #px"^([0-9]|[a-f]){32}$"))]
          ))

(define (aes block key)
  (detail-div
   #:font_size? 'small
   (lambda ()
     (let ([nb 4]
           [nk #f]
           [nr #f]
           [key_size (string-length key)])

       (detail-h1 "AES Encryption")
          
       (detail-h2 "Input")
          
       (detail-list
        (lambda ()
          (detail-row (lambda () (detail-col "block data:") (detail-col block)))
          
          (detail-row (lambda () (detail-col "key:") (detail-col key)))

          (cond
           [(= key_size 32)
            (set! nk 4)
            (set! nr 10)]
           [(= key_size 48)
            (set! nk 6)
            (set! nr 12)]
           [(= key_size 64)
            (set! nk 8)
            (set! nr 14)])
          
          (detail-row (lambda () (detail-col "key size:") (detail-col (number->string key_size))))

          (detail-row (lambda () (detail-col "nk:") (detail-col (number->string nk))))

          (detail-row (lambda () (detail-col "nr:") (detail-col (number->string nr))))))
       
       (let ([w (key-expansion key nk nr)]
             [state block])

         (detail-h2 "Cipher Start")

         (detail-list
          (lambda ()
            (detail-row (lambda () (detail-col "round[0].input: ") (detail-col state)))

            (detail-row (lambda () (detail-col "round[0].k_sch") (detail-col (list-ref w 0))))

            (set! state (add-round-key state (list-ref w 0)))
            
            (let loop ([round 1])
              (when (<= round (sub1 nr))
                (detail-row (lambda () (detail-col (format "round[~a].start" round)) (detail-col state)))

                (set! state (sub-block state))

                (detail-row (lambda () (detail-col (format "round[~a].s_box" round)) (detail-col state)))
                
                (set! state (shift-rows state))

                (detail-row (lambda () (detail-col (format "round[~a].s_row" round)) (detail-col state)))
                
                (set! state (mix-columns state))

                (detail-row (lambda () (detail-col (format "round[~a].m_col" round)) (detail-col state)))

                (set! state (add-round-key state (list-ref w round)))

                (detail-row (lambda () (detail-col (format "round[~a].k_sch" round)) (detail-col (list-ref w round))))
                
                (loop (add1 round))))

            (set! state (sub-block state))

            (detail-row (lambda () (detail-col (format "round[~a].s_box" nr)) (detail-col state)))

            (set! state (shift-rows state))

            (detail-row (lambda () (detail-col (format "round[~a].s_row" nr)) (detail-col state)))

            (set! state (add-round-key state (list-ref w nr)))

            (detail-row (lambda () (detail-col (format "round[~a].k_sch" nr)) (detail-col (list-ref w nr))))

            (detail-row (lambda () (detail-col (format "round[~a].output" nr)) (detail-col state)))
            ))

         (detail-h2 "Cipher End")
            
         (detail-line state #:font_size? 'big #:line_break_length? 32)
         
         state)))))

(define (unaes block key)
  (detail-div 
   #:font_size? 'small
   (lambda ()

     (let ([nb 4]
           [nk #f]
           [nr #f]
           [key_size (string-length key)])

       (detail-h1 "AES Decryption")
          
       (detail-h2 "Input")
          
       (detail-list
        (lambda ()
          (detail-row (lambda () (detail-col "block data:") (detail-col block)))

          (detail-row (lambda () (detail-col "key:") (detail-col key)))

          (cond
           [(= key_size 32)
            (set! nk 4)
            (set! nr 10)]
           [(= key_size 48)
            (set! nk 6)
            (set! nr 12)]
           [(= key_size 64)
            (set! nk 8)
            (set! nr 14)])
          
          (detail-row (lambda () (detail-col "key size:") (detail-col (number->string key_size))))

          (detail-row (lambda () (detail-col "nk:") (detail-col (number->string nk))))

          (detail-row (lambda () (detail-col "nr:") (detail-col (number->string nr))))))
       
       (let ([w (key-expansion key nk nr)]
             [state block])

         (detail-h2 "InvCipher Start")

         (detail-list
          (lambda ()
            (detail-row (lambda () (detail-col "round[0].iinput: ") (detail-col state)))

            (detail-row (lambda () (detail-col "round[0].ik_sch") (detail-col (list-ref w nr))))

            (set! state (add-round-key state (list-ref w nr)))

            (let loop ([round 1])
              (when (<= round (sub1 nr))
                (detail-row (lambda () (detail-col (format "round[~a].istart" round)) (detail-col state)))

                (set! state (inv-shift-rows state))

                (detail-row (lambda () (detail-col (format "round[~a].is_row" round)) (detail-col state)))

                (set! state (inv-sub-block state))

                (detail-row (lambda () (detail-col (format "round[~a].is_box" round)) (detail-col state)))

                (detail-row (lambda () (detail-col (format "round[~a].ik_sch" round)) (detail-col (list-ref w (- nr round)))))

                (set! state (add-round-key state (list-ref w (- nr round))))

                (detail-row (lambda () (detail-col (format "round[~a].ik_add" round)) (detail-col state)))
                
                (set! state (inv-mix-columns state))

                (loop (add1 round))))

            (set! state (inv-shift-rows state))

            (detail-row (lambda () (detail-col (format "round[~a].is_row" nr)) (detail-col state)))

            (set! state (inv-sub-block state))

            (detail-row (lambda () (detail-col (format "round[~a].is_box" nr)) (detail-col state)))

            (set! state (add-round-key state (list-ref w 0)))

            (detail-row (lambda () (detail-col (format "round[~a].ik_sch" nr)) (detail-col (list-ref w 0))))

            (detail-row (lambda () (detail-col (format "round[~a].output" nr)) (detail-col state)))
            ))

         (detail-h2 "InvCipher End")
            
         (detail-line state #:font_size? 'big #:line_break_length? 32)
         
         state)))))


