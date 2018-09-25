{-# LANGUAGE OverloadedStrings #-}

module Data.KDBX.Header
  ( Header(..)
  , Cipher(..)
  , CompressionAlgorithm(..)
  , CrsAlgorithm(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Serialize
import Data.Version (Version, makeVersion)
import Data.Word

data Header = Header
  { hVersion :: Version
  , hComment :: Maybe ByteString
  , hCipher :: Cipher
  , hCompression :: CompressionAlgorithm
  , hMasterSeed :: ByteString
  , hTransformSeed :: ByteString
  , hTransformRounds :: Integer
  , hEncryptionIV :: ByteString
  , hStreamKey :: ByteString
  , hStartBytes :: ByteString
  , hStreamID :: CrsAlgorithm
  } deriving (Show)

instance Serialize Header where
  put = fail "Not yet implemented"
  get = do
    label "Verifying Signature" verifySignature
    result <- makeHeader <$> getVersion <*> getFields
    either fail pure result
    where
      verifySignature = (==signature) <$> getTwoOf getWord32le getWord32le

makeHeader :: Version -> [(HeaderField, ByteString)] -> Either String Header
makeHeader version fields =
  Header version (lookup Comment fields)
    <$> getField get CipherUUID
    <*> getField get Compression
    <*> getField all MasterSeed
    <*> getField all TransformSeed
    <*> getField getRounds TransformRounds
    <*> getField all EncryptionIV
    <*> getField all StreamKey
    <*> getField all StartBytes
    <*> getField get StreamID
  where
    all = getByteString =<< remaining
    getRounds = isolate 8 (fmap fromIntegral getWord64le)
    getField getter a =
      case lookup a fields of
        Just result -> runGet getter result
        Nothing -> Left $ "Missing header field: " <> show a

data Cipher
  = AES
  | ChaCha20
  deriving (Show)

instance Serialize Cipher where
  put = fail "Not yet implemented"
  get = do
    identifier <- isolate 16 (getByteString =<< remaining)
    pure $ case identifier of
      "\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff" -> AES
      "\xd6\x03\x8a\x2b\x8b\x6f\x4c\xb5\xa5\x24\x33\x9a\x31\xdb\xb5\x9a" -> ChaCha20

data CompressionAlgorithm
  = None
  | GZip
  deriving (Show)

instance Serialize CompressionAlgorithm where
  put = fail "Not yet implemented"
  get = do
    identifier <- isolate 4 getWord32le
    case identifier of
      0 -> pure None
      1 -> pure GZip
      _ -> fail $ "Unknown compression algorithm with identifier: " <> show identifier

data CrsAlgorithm
  = Arc4
  | Salsa20
  | ChaCha20'Crs
  deriving (Show)

instance Serialize CrsAlgorithm where
  put = fail "Not yet implemented"
  get = do
    identifier <- isolate 4 getWord32le
    case identifier of
      1 -> pure Arc4
      2 -> pure Salsa20
      3 -> pure ChaCha20'Crs
      _ -> fail $ "Unknown crs algorithm with identifier: " <> show identifier

data HeaderField
  = EndOfHeader
  | Comment
  | CipherUUID
  | Compression
  | MasterSeed
  | TransformSeed
  | TransformRounds
  | EncryptionIV
  | StreamKey
  | StartBytes
  | StreamID
  deriving (Show, Eq, Enum)

instance Serialize HeaderField where
  put = putWord8 . fromIntegral . fromEnum
  get = toEnum . fromIntegral <$> getWord8

signature :: (Word32, Word32)
signature = (0x9aa2d903, 0xb54bfb67)

getVersion :: Get Version
getVersion = do
  min <- fromIntegral <$> getWord16le
  maj <- fromIntegral <$> getWord16le
  pure $ makeVersion [maj, min]

getFields :: Get [(HeaderField, ByteString)]
getFields = getFields' []
  where
    getLength = fromIntegral <$> getWord16le
    getFields' acc = do
      field <- getTwoOf get (getByteString =<< getLength)
      case fst field of
        EndOfHeader -> pure acc
        _ -> getFields' (field : acc)
