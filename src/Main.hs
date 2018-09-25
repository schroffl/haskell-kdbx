{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import Data.Serialize
import Data.KDBX.Header

main :: IO ()
main = print =<< test

test :: IO Header
test = either fail pure . decode =<< BS.readFile "test.kdbx"
