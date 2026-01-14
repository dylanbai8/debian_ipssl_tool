package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	IPAddr       string   `json:"ip_addr"`
	Webroot      string   `json:"webroot"`
	Email        string   `json:"email"`
	RenewDays    int      `json:"renew_days"`
	InstallPaths []string `json:"install_paths"`
	WebEnable    bool     `json:"web_enable"`
	WebUser      string   `json:"web_user"`
	WebPass      string   `json:"web_pass"`
}

var (
	cfg      Config
	basePath string
	logFile  *os.File
)

func initBasePath() {
	exe, _ := os.Executable()
	basePath = filepath.Dir(exe)
}

func safePath(p string) string {
	return filepath.Join(basePath, p)
}

func initLog() {
	f, _ := os.OpenFile(safePath("cert-manager.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	log.SetOutput(f)
	logFile = f
}

func rotateLog() {
	p := safePath("cert-manager.log")
	if fi, err := os.Stat(p); err == nil && time.Since(fi.ModTime()) > 30*24*time.Hour {
		os.Remove(p)
	}
}

func killOld() {
	out, _ := exec.Command("pgrep", "-f", os.Args[0]).Output()
	for _, pid := range strings.Fields(string(out)) {
		if pid != fmt.Sprint(os.Getpid()) {
			syscall.Kill(toInt(pid), syscall.SIGTERM)
		}
	}
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func initFiles() {
	cfgPath := safePath("config.json")
	webPath := safePath("web/index.html")

	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		os.WriteFile(cfgPath, []byte(`{
  "ip_addr": "166.108.238.105",
  "webroot": "/www/wwwroot/166.108.238.105",
  "email": "example@qq.com",
  "renew_days": 3,
  "install_paths": [
    "/www/server/panel/vhost/cert/166.108.238.105"
  ],
  "web_enable": true,
  "web_user": "admin",
  "web_pass": "123456"
}`), 0644)
	}

	if _, err := os.Stat(webPath); os.IsNotExist(err) {
		os.MkdirAll(filepath.Dir(webPath), 0755)
		os.WriteFile(webPath, []byte(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>证书管理</title></head>
<body>
<h2>证书管理</h2>
<textarea id="cfg" style="width:600px;height:300px;"></textarea><br>
<button onclick="save()">保存配置</button>
<button onclick="issue()">签发证书</button>
<div id="msg" style="color:green;margin-top:10px;"></div>

<script>
fetch('/api/config').then(r=>r.json()).then(j=>{
 document.getElementById('cfg').value = JSON.stringify(j,null,2)
})

function flash(t,color){
 let m=document.getElementById('msg');
 m.style.color=color; m.innerText=t;
 setTimeout(()=>{m.innerText=''},1000)
}

function save(){
 fetch('/api/config',{method:'POST',body:document.getElementById('cfg').value}).then(r=>r.text()).then(t=>{
   if(t==='ok') flash('✔ 保存成功','green');
   else flash('✖ '+t,'red');
 })
}

function issue(){
 fetch('/api/issue',{method:'POST'}).then(()=>flash('✔ 任务已提交','green'))
}
</script>
</body>
</html>`), 0644)
	}
}

func loadConfig() {
	b, _ := os.ReadFile(safePath("config.json"))
	json.Unmarshal(b, &cfg)
}

func saveConfig(b []byte) error {
	var tmp Config
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	cfg = tmp
	return os.WriteFile(safePath("config.json"), b, 0644)
}

func auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !cfg.WebEnable {
			w.WriteHeader(403)
			w.Write([]byte("Web管理已关闭"))
			return
		}
		rawAuth := r.Header.Get("Authorization")
		if rawAuth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="cert-manager"`)
			w.WriteHeader(401)
			return
		}
		raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(rawAuth, "Basic "))
		parts := strings.SplitN(string(raw), ":", 2)
		if len(parts) != 2 || parts[0] != cfg.WebUser || parts[1] != cfg.WebPass {
			w.WriteHeader(403)
			return
		}
		h(w, r)
	}
}

func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		log.Println("获取外网IP失败:", err)
		return "未知"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}

func issueCert() {
	defer func() {
		if r := recover(); r != nil {
			log.Println("任务异常:", r, string(debug.Stack()))
		}
	}()

	log.Println("=== 证书任务开始 ===")
	run("sh", "-c", "curl https://get.acme.sh | sh -s email="+cfg.Email)
	run(filepath.Join(os.Getenv("HOME"), ".acme.sh/acme.sh"), "--set-default-ca", "--server", "letsencrypt")
	run(filepath.Join(os.Getenv("HOME"), ".acme.sh/acme.sh"),
		"--issue", "--server", "letsencrypt", "--certificate-profile", "shortlived",
		"--days", strconv.Itoa(cfg.RenewDays), "-d", cfg.IPAddr, "-w", cfg.Webroot)

	for _, p := range cfg.InstallPaths {
		os.MkdirAll(p, 0755)
		run(filepath.Join(os.Getenv("HOME"), ".acme.sh/acme.sh"),
			"--install-cert", "-d", cfg.IPAddr,
			"--key-file", p+"/privkey.pem", "--fullchain-file", p+"/fullchain.pem")
	}

	run("nginx", "-t")
	run("nginx", "-s", "reload")
	log.Println("=== 证书任务结束 ===")
}

func run(cmd string, args ...string) {
	c := exec.Command(cmd, args...)
	c.Stdout = logFile
	c.Stderr = logFile
	if err := c.Run(); err != nil {
		log.Println("命令失败:", cmd, err)
	}
}

func main() {
	killOld()
	initBasePath()
	rotateLog()
	initLog()
	initFiles()
	loadConfig()

	fmt.Println("配置文件路径:", safePath("config.json"))
	fmt.Println("管理页面外网地址: http://" + getPublicIP() + ":8080")

	go func() {
		t := time.NewTicker(6 * time.Hour)
		for range t.C {
			log.Println("自动任务触发")
			issueCert()
		}
	}()

	if cfg.WebEnable {
		mux := http.NewServeMux()
		mux.Handle("/", auth(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, safePath("web/index.html"))
		}))
		mux.HandleFunc("/api/config", auth(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				json.NewEncoder(w).Encode(cfg)
			} else if r.Method == "POST" {
				b, _ := io.ReadAll(r.Body)
				if err := saveConfig(b); err != nil {
					w.Write([]byte("JSON格式错误: " + err.Error()))
					return
				}
				w.Write([]byte("ok"))
			}
		}))
		mux.HandleFunc("/api/issue", auth(func(w http.ResponseWriter, r *http.Request) {
			go issueCert()
			w.Write([]byte("started"))
		}))

		go http.ListenAndServe(":8080", mux)
	} else {
		fmt.Println("Web 管理已禁用")
	}

	select {}
}
