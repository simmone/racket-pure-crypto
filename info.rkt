#lang setup/infotab

(define version "1.0")

(define collection 'multi)

(define deps '("base"
               "rackunit-lib"
               "racket-doc"
               "scribble-lib"
               "detail"
               ))

(define test-omit-paths '("info.rkt"))
