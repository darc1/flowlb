package lb

import (
	"syscall"
	"time"
	"unsafe"
)

var(
  CLOCK_MONOTONIC = 1
)

type time_t struct {
  seconds uint64
  nanoseconds int64
}


func GetMonoNowNano() uint64{

      t := &time_t{}
      res := uintptr(unsafe.Pointer(t))
      _,_,erro := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, uintptr(CLOCK_MONOTONIC), res ,0)

      if erro != 0 {
        return 0
      }

      return uint64(t.nanoseconds) + t.seconds*uint64(time.Second)
      
}


