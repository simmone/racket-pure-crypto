#lang info

(define version "1.0")

(define license
  '(Apache-2.0 OR MIT))

(define collection 'multi)

(define deps '("base"
               "rackunit-lib"
               "racket-doc"
               "scribble-lib"
               ))

(define test-omit-paths '("info.rkt"))
