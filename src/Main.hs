{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Control.Applicative as Applicative
import qualified Crypto.KDF.Argon2 as A2
import qualified Crypto.Error as CE
import qualified Data.ByteString.Char8 as BS
import Text.Printf (printf)
import Data.Attoparsec.ByteString as Attoparsec
import Data.Attoparsec.Binary
import Data.Word
import Debug.Trace (traceShowId, trace)

main :: IO ()
main = print =<< run

run :: IO (Either String KDBX)
run = do
  content <- BS.readFile "test.kdbx"
  return . eitherResult $ parse kdbxParser content

data KDBX = KDBX
  { kdbxSignatures :: (Word32, Word32)
  , kdbxVersion :: (Word16, Word16)
  , kdbxFields :: [HeaderField]
  } deriving (Show, Eq)

data HeaderField
  = CipherUUID BS.ByteString
  | CompressionFlags Word32
  | MasterSeed BS.ByteString
  | TransformSeed BS.ByteString
  | TransformRounds Int
  | EncryptionIV BS.ByteString
  | StreamKey BS.ByteString
  | StartBytes BS.ByteString
  | StreamID Int
  | Comment BS.ByteString
  | EndOfHeader
  deriving (Show, Eq)

kdbxParser :: Parser KDBX
kdbxParser = do
  signatures <- (,) <$> anyWord32le <*> anyWord32le
  version <- flip (,) <$> anyWord16le <*> anyWord16le
  if signatures /= (0x9AA2D903, 0xB54BFB67) || version /= (3, 1)
    then fail $ "Unknown values: " <> show signatures <> " " <> show version
    else return ()
  fields <- count 10 fieldParser
  pure $ KDBX signatures version fields

fieldParser :: Parser HeaderField
fieldParser = do
  type' <- anyWord8
  len <- fromIntegral <$> anyWord16le
  case type' of
    0 -> return EndOfHeader
    1 -> Comment <$> Attoparsec.take len
    2 -> CipherUUID <$> Attoparsec.take len
    3 -> CompressionFlags <$> anyWord32le
    4 -> MasterSeed <$> Attoparsec.take len
    5 -> TransformSeed <$> Attoparsec.take len
    6 -> TransformRounds . fromIntegral <$> anyWord64le
    7 -> EncryptionIV <$> Attoparsec.take len
    8 -> StreamKey <$> Attoparsec.take len
    9 -> StartBytes <$> Attoparsec.take len
    10 -> StreamID . fromIntegral <$> anyWord32le
    _ -> fail $ "Unknown header field of type '" <> show type' <> "'"
