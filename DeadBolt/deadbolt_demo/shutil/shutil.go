package shutil


import (
  "fmt"
)


func BinToStr(data []byte) (s string) {

  for _, b := range data {
    if (b >= 0x30) && (b <= 0x5A) || ((b >= 0x61) && (b <= 0x7E)) {
      s += fmt.Sprintf("%c", b)
    } else {
      s += fmt.Sprintf("\\x%02x", b)
    }
  }

  return s
}
