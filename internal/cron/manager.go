package cron

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"netkit/internal/config"
	"netkit/internal/logcenter"
	"netkit/internal/safe"
)

// Manager 计划任务调度器。
type Manager struct {
	mu      sync.Mutex
	running map[string]*runningTask
}

type runningTask struct {
	stop    chan struct{}
	done    chan struct{}
	task    config.CronTask
	sched   *Schedule
	logs    *safe.LogRing
	lastRun string
	lastOK  bool
	running bool
}

func NewManager() *Manager {
	return &Manager{running: map[string]*runningTask{}}
}

func (m *Manager) Logs(id string) []string {
	m.mu.Lock()
	rt := m.running[id]
	m.mu.Unlock()
	if rt == nil {
		return nil
	}
	return rt.logs.Snapshot()
}

// RunNow 手动立即执行一次。
func (m *Manager) RunNow(id string) error {
	m.mu.Lock()
	rt := m.running[id]
	m.mu.Unlock()
	if rt == nil {
		return fmt.Errorf("任务未启用或不存在")
	}
	go m.execOnce(rt, "手动执行")
	return nil
}

// Apply 增量启停任务。
func (m *Manager) Apply(cfgs []config.CronTask) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, rt := range m.running {
		keep := false
		for _, c := range cfgs {
			if c.ID == id {
				keep = c.Enabled && fmt.Sprint(rt.task) == fmt.Sprint(c)
				break
			}
		}
		if !keep {
			close(rt.stop)
			<-rt.done
			delete(m.running, id)
		}
	}
	for _, c := range cfgs {
		if !c.Enabled {
			continue
		}
		if _, ok := m.running[c.ID]; ok {
			continue
		}
		sched, err := Parse(c.Cron)
		if err != nil {
			logcenter.Default().Add("计划任务", logcenter.LevelError, "任务 %s cron 表达式无效: %v", c.Name, err)
			continue
		}
		rt := &runningTask{
			stop: make(chan struct{}), done: make(chan struct{}),
			task: c, sched: sched, logs: safe.NewLogRing(100),
		}
		m.running[c.ID] = rt
		go m.loop(rt)
	}
}

func (m *Manager) loop(rt *runningTask) {
	defer close(rt.done)
	logcenter.Default().Add("计划任务", logcenter.LevelInfo, "任务 [%s] 已启动 (cron: %s)", rt.task.Name, rt.task.Cron)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	lastMin := int64(-1)
	for {
		select {
		case <-rt.stop:
			return
		case now := <-t.C:
			if now.Unix()/60 == lastMin {
				continue
			}
			lastMin = now.Unix() / 60
			if rt.sched.Match(now) {
				m.execOnce(rt, "")
			}
		}
	}
}

func (m *Manager) execOnce(rt *runningTask, tag string) {
	m.mu.Lock()
	if rt.running {
		m.mu.Unlock()
		rt.logs.Add(time.Now().Format("2006-01-02 15:04:05") + " [跳过] 上一次执行尚未结束")
		return
	}
	rt.running = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		rt.running = false
		m.mu.Unlock()
	}()

	timeout := rt.task.TimeoutSec
	if timeout <= 0 {
		timeout = 60
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cmd", "/C", rt.task.Command)
	if isUnix() {
		cmd = exec.CommandContext(ctx, "sh", "-c", rt.task.Command)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()

	rt.lastRun = time.Now().Format("2006-01-02 15:04:05")
	rt.lastOK = err == nil
	prefix := "定时执行"
	if tag != "" {
		prefix = tag
	}
	result := "成功"
	level := logcenter.LevelInfo
	if err != nil {
		result = fmt.Sprintf("失败: %v", err)
		level = logcenter.LevelError
	}
	o := out.String()
	if len(o) > 2000 {
		o = o[:2000] + "…"
	}
	rt.logs.Add(fmt.Sprintf("%s [%s] %s\n%s", rt.lastRun, prefix, result, o))
	logcenter.Default().Add("计划任务", level, "任务 [%s] %s: %s", rt.task.Name, prefix, result)
}

func isUnix() bool {
	return !isWindows()
}

func isWindows() bool {
	return os.PathSeparator == '\\'
}

// Status 任务状态汇总。
func (m *Manager) Status() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for id, rt := range m.running {
		st := "等待调度"
		if rt.lastRun != "" {
			st = "最近执行 " + rt.lastRun
			if !rt.lastOK {
				st += "（失败）"
			}
		}
		if rt.running {
			st += " | 执行中"
		}
		out[id] = st
	}
	return out
}

var defaultCron = NewManager()

// Default 返回计划任务模块单例。
func Default() *Manager { return defaultCron }
