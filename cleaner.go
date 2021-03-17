package lb

import (
	"net"
	"time"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
)

type ConnectionCleaner interface{
  CleanLoop() (error)
}

type ConnectionCleanerLoop struct {
  ttl_sec uint64;
  flows *bpf.Table
  connTracker *ConnTracker

}

func (cleaner *ConnectionCleanerLoop) CleanLoop(){
    for {

      cleaner.Clean()
      time.Sleep(1*time.Second) 
    }
}

func (cleaner *ConnectionCleanerLoop) Clean(){

  cleaner.connTracker.ForEach(func(key net.Addr, trackedConn *TrackedConn) bool {
      if trackedConn == nil {
        log.Warnf("found nil conn for: %s", key.String()) 
        cleaner.connTracker.deleteConn(key)
        return true
      }
      
      unixNow := time.Now().UnixNano()
      init_elapsed_sec := (unixNow - trackedConn.timestamp)/int64(time.Second) 
      if !trackedConn.isInstalled(){
        if  init_elapsed_sec > int64(cleaner.ttl_sec) {
          log.Debugf("conn: %s not installed after ttl, deleting", trackedConn)
          cleaner.removeConn(key, trackedConn)
          
        }
        return true
      }
      
      flowKey, _, err := trackedConn.getFlowValues()
      if err != nil {
        log.Errorf("failed to get flow key for: %s", trackedConn)
        return true
      }

      flowValP, err := cleaner.flows.GetP(unsafe.Pointer(flowKey)) 
      if err != nil || flowValP == nil {
        log.Errorf("failed to get flow entry for conn: %s",trackedConn)
        return true
      }

      monoNow := GetMonoNowNano()
      if monoNow == 0 {
        log.Errorf("failed to get mono time")
        return true
      }

      flowVal := (*(*FlowValue)(flowValP))
            
      elapsed := (monoNow - flowVal.lastUsed)/uint64(time.Second)
      
      if elapsed > cleaner.ttl_sec {
        log.Debugf("conn:%s last used in %d sec ttl expired, deleting", trackedConn, elapsed)
        cleaner.removeConn(key, trackedConn)

      }
      return true
    })
}

func (cleaner *ConnectionCleanerLoop) removeConn(key net.Addr, trackedConn *TrackedConn){
    
  if trackedConn.isInstalled(){
    flow_key, _, err := trackedConn.getFlowValues()
    if err != nil {
          log.Errorf("failed to get flow values for conn: %s", trackedConn)
    } else {
      cleaner.flows.DeleteP(unsafe.Pointer(flow_key))
    }
    snat_key, _, err := trackedConn.getSrcNatValues()
    if err != nil {
          log.Errorf("failed to get snat values for conn: %s", trackedConn)
    } else {
      cleaner.flows.DeleteP(unsafe.Pointer(snat_key))
    }
  }

  cleaner.connTracker.deleteConn(key)
  log.Infof("removed conn: %s, lastUsed > %d", trackedConn, cleaner.ttl_sec)

}

