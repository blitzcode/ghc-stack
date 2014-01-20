
module Main where

import Data.Vector.Mutable

main :: IO ()
main = do
    someFuncA
    someFuncB

{-# NOINLINE someFuncA #-}
someFuncA :: IO ()
someFuncA = do
    v <- new 100
    unsafeWrite v 0 (0 :: Int)

{-# NOINLINE someFuncB #-}
someFuncB :: IO ()
someFuncB = do
    someFuncC
    someFuncC

{-# NOINLINE someFuncC #-}
someFuncC :: IO ()
someFuncC = do
    v <- new 100
    --unsafeWrite v 1000000000 (0 :: Int) -- Crash (hopefully)
    unsafeWrite v 0 (0 :: Int)
    c_someCFuncA

foreign import ccall unsafe "crash.h someCFuncA"
    c_someCFuncA :: IO ()

