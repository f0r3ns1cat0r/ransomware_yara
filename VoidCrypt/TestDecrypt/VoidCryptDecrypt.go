package main


import (
  "os"
  "io"
  "flag"
  "bufio"
  "fmt"
  "errors"
  "strings"
  "path/filepath"
  "encoding/base64"
  "crypto/x509"
  "crypto/rsa"
  "crypto/rand"
  "crypto/sha1"
  "crypto/cipher"
  "crypto/aes"
)


// Encrypted metadata size
const EncMetadataSize = 256
// Encrypted metadata marker size
const EncMetadataMarkerSize = 3
// Max encrypted size
const MaxEncDataSize = 400000
// AES key size
const AESKeySize = 32
// AES GCM nonce size
const AESGCMNonceSize = 12


// Main
func main() {

  argRansomExt := flag.String("ext", "", "Encrypted file extension")
  argKeyFileName := flag.String("key", "rsa_privkey.txt",
                                "RSA private key file path")

  flag.Parse()

  keyFileName := *argKeyFileName
  cmdArgs := flag.Args()

  if (len(cmdArgs) < 1) || (keyFileName == "") {
    fmt.Println("Usage: " + filepath.Base(os.Args[0]) +
                "[-ext ransom_ext] [-key key_path] filename")
    os.Exit(0)
  }

  fileName := cmdArgs[0]

  // Import RSA private key from file
  rsaPrivKey, err := ImportRSAPrivateKeyFromFile(keyFileName)
  if err != nil {
    fmt.Println("Error:", err.Error())
    os.Exit(1)
  }

  fmt.Printf("RSA private key size: %d\n", rsaPrivKey.Size() * 8)

  var newFileName string

  ransomExt := *argRansomExt
  if (ransomExt != "") && (ransomExt[0] != '.') {
    ransomExt = "." + ransomExt
  }

  if (ransomExt != "") && strings.HasSuffix(fileName, ransomExt) {
    newFileName = fileName[:len(fileName) - len(ransomExt)]
  } else {
    newFileName = fileName + ".dec"
  }

  // Copy and decrypt file
  err = CopyAndDecryptFile(fileName, newFileName, rsaPrivKey)
  if err != nil {
    fmt.Println("Error:", err.Error())
    os.Exit(1)
  }
}


// Copy and decrypt file
func CopyAndDecryptFile(fileName, newFileName string,
                        rsaPrivKey *rsa.PrivateKey) (err error) {

  // Copy file
  err = CopyFile(fileName, newFileName)
  if err != nil { return err }

  // Decrypt file
  err = DecryptFile(newFileName, rsaPrivKey)
  if err != nil {
    // Delete file
    os.Remove(newFileName)
    return err
  }

  return nil
}


// Decrypt file
func DecryptFile(fileName string, rsaPrivKey *rsa.PrivateKey) (err error) {

  f, err := os.OpenFile(fileName, os.O_RDWR, 0600)
  if err != nil { return err }

  defer f.Close()

  fileInfo, err := f.Stat()
  if err != nil { return err }

  fileSize := fileInfo.Size()

  if fileSize < EncMetadataMarkerSize + EncMetadataSize {
    return errors.New("Encrypted file is too small")
  }

  fileSize -= EncMetadataSize

  var bytesRead int

  encMetadata := make([]byte, EncMetadataSize)
  bytesRead, err = f.ReadAt(encMetadata[:], fileSize)
  if err != nil { return err }

  // RSA-OAEP decrypt metadata
  metadata, err := RSADecrypt(encMetadata[:bytesRead], rsaPrivKey)
  if err != nil { return err }

  fileSize -= EncMetadataMarkerSize

  aesKey := metadata[:AESKeySize]
  nonce := metadata[AESKeySize : AESKeySize + AESGCMNonceSize]

  c, err := aes.NewCipher(aesKey)
  if err != nil { return err }

  aesgcm, err := cipher.NewGCM(c)
  if err != nil { return err }

  encDataSize := MaxEncDataSize
  if int64(encDataSize) > fileSize {
    encDataSize = int(fileSize)
  }

  buf := make([]byte, encDataSize)

  bytesRead, err = f.ReadAt(buf[:encDataSize], 0)
  if err != nil { return err }

  // AES GCM decrypt
  buf, err = aesgcm.Open(buf[:0], nonce, buf[:bytesRead], nil)
  if err != nil { return err }

  _, err = f.WriteAt(buf, 0)
  if err != nil { return err }

  if int64(encDataSize) == fileSize {
    fileSize = int64(len(buf))
  }

  err = f.Truncate(fileSize)
  if err != nil { return err }

  return nil
}


// RSA-OAEP decrypt data
func RSADecrypt(data []byte, privKey *rsa.PrivateKey) ([]byte, error) {

  hash := sha1.New()

  rng := rand.Reader

  decData, err := rsa.DecryptOAEP(hash, rng, privKey, data, nil)
  if err != nil { return nil, err }

  return decData, nil
}


// Import RSA private key from file
func ImportRSAPrivateKeyFromFile(fileName string) (*rsa.PrivateKey, error) {

  f, err := os.Open(fileName)
  if err != nil { return nil, err }
  defer f.Close()

  fileInfo, err := f.Stat()
  if err != nil { return nil, err }

  fileSize := fileInfo.Size()
  keyBase64Data := make([]byte, fileSize)

  buf := bufio.NewReader(f)
  bytesRead, err := buf.Read(keyBase64Data)
  if err != nil { return nil, err }

  keyBase64Str := string(keyBase64Data[:bytesRead])
  keyData, err := base64.StdEncoding.DecodeString(keyBase64Str)
  if err != nil { return nil, err }

  key, err := x509.ParsePKCS8PrivateKey(keyData)
  if err != nil { return nil, err }

  switch key := key.(type) {
    case *rsa.PrivateKey:
      return key, nil
    default:
      return nil, errors.New("Unknown private key type in PKCS#8 wrapping")
  }
}


// Copy file
func CopyFile(fileName, newFileName string) (err error) {

  file, err := os.Open(fileName)
  if err != nil { return err }
  defer file.Close()
 
  // Create new file
  newFile, err := os.Create(newFileName)
  if err != nil { return err }
  defer newFile.Close()
 
  _, err = io.Copy(newFile, file)

  return err
}
