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
import Data.Version (Version, makeVersion, versionBranch)
import Data.Word
import Data.Foldable (traverse_)
import Prelude hiding (min, all)

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
  put header = do
    putWord32le $ fst signature
    putWord32le $ snd signature
    putVersion $ hVersion header
    maybe (pure ()) (putField . (,) Comment) $ hComment header
    traverse_ putField . map ($header) $
      [ (,) CipherUUID . encode . hCipher
      , (,) Compression . encode . hCompression
      , (,) MasterSeed . hMasterSeed
      , (,) TransformSeed . hTransformSeed
      , (,) TransformRounds . encodeRounds . hTransformRounds
      , (,) EncryptionIV . hEncryptionIV
      , (,) StreamKey . hStreamKey
      , (,) StartBytes . hStartBytes
      , (,) StreamID . encode . hStreamID
      ]
    putField (EndOfHeader, "")
    where
      putLength = putWord16le . fromIntegral . BS.length
      encodeRounds = runPut . putWord64le . fromIntegral
      putField (field, data') = do
        put field
        putLength data'
        putByteString data'

  get = do
    _ <- label "Verifying Signature" verifySignature
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
  put cipher = putByteString $
    case cipher of
      AES -> "\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff"
      ChaCha20 -> "\xd6\x03\x8a\x2b\x8b\x6f\x4c\xb5\xa5\x24\x33\x9a\x31\xdb\xb5\x9a" 

  get = do
    identifier <- isolate 16 (getByteString =<< remaining)
    case identifier of
      "\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff" -> pure AES
      "\xd6\x03\x8a\x2b\x8b\x6f\x4c\xb5\xa5\x24\x33\x9a\x31\xdb\xb5\x9a" -> pure ChaCha20
      _ -> fail $ "Unknown Cipher with UUID: " <> show identifier

data CompressionAlgorithm
  = None
  | GZip
  deriving (Show)

instance Serialize CompressionAlgorithm where
  put None = putWord32le 0
  put GZip = putWord32le 1
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
  put Arc4 = putWord32le 1
  put Salsa20 = putWord32le 2
  put ChaCha20'Crs = putWord32le 3
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

putVersion :: Putter Version
putVersion v = do
  putWord16le min
  putWord16le maj
  where
    [maj, min] = map fromIntegral $ versionBranch v

getFields :: Get [(HeaderField, ByteString)]
getFields = getFields' []
  where
    getLength = fromIntegral <$> getWord16le
    getFields' acc = do
      field <- getTwoOf get (getByteString =<< getLength)
      case fst field of
        EndOfHeader -> pure acc
        _ -> getFields' (field : acc)
