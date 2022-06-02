package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

func main() {
	options := ParseOptions()

	datedir := options.ResultDir
	filepath := options.ScanFile

	isExists, _ := PathExists(datedir)
	if !isExists {
		err := os.Mkdir(datedir, os.ModePerm)
		if err != nil {
			log.Println(err)
		}
	}

	urls, err := ReadFileByLine(filepath)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	urlsCount := len(urls)

	//乱序
	DisruptedOrder(urls)
	f, err := os.Create("url.bak")
	if err != nil {
		log.Printf("create map file error: %v\n", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, v := range urls {
		fmt.Fprintln(w, v)
	}
	w.Flush()

	payloads, err := ReadFileByLine("payloads.txt")
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}

	g := NewGlimit(options.MaxConcurrency)
	wg := sync.WaitGroup{}

	for ct, surl := range urls {

		i := ct
		myurl := surl

		time.Sleep(time.Millisecond * 100)

		wg.Add(1)
		goFunc := func() {
			defer wg.Done()

			myurl := strings.TrimSpace(myurl)
			if IsBlack(myurl, UrlBlackList) {
				log.Printf("[%d/%d][Blacklist]%s", i+1, urlsCount, myurl)
				return
			}
			log.Printf("[%d/%d]%s", i+1, urlsCount, myurl)
			var su ScanUrl
			err := su.Parse(myurl)
			if err != nil {
				fmt.Println("[ERROR]", myurl, err)
				return
			}

			//  fuzz url struct  to url string
			var fuzz_urls []string
			for _, payload := range payloads {
				tmp_url := su.Scheme + "://" + su.Host + payload
				fuzz_urls = append(fuzz_urls, tmp_url)
			}

			xlauncher := launcher.New().
				// Headless(false).
				NoSandbox(true)

			l, errL := xlauncher.Launch()
			if errL != nil {
				// xb.log.Warn("[xbrowser][Init]Launch Error:", errL)
				log.Println("[Domxss][Init]Launch Error:", errL)
				return
			}
			// cdp := cdp.New()
			agentBrowser := rod.New().
				ControlURL(l).
				// Trace(true).
				// SlowMotion(1 * time.Second).
				MustConnect()

			page, err := agentBrowser.Page(proto.TargetCreateTarget{URL: strings.Join([]string{}, "/")})
			if err != nil {
				log.Println("Create Page err:", err, myurl)
				return
			}
			_ = proto.NetworkEnable{}.Call(page)

			// 【异步处理事件】如弹窗问题，如 onbeforeunload 这样的弹窗。
			go page.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
				if strings.Contains(e.Message, "20220510") {
					log.Println("[Vul]", e.URL, "popup!")
					fu := e.URL
					msg := fmt.Sprintf("%s\n\t%s\n", fu, "popup!")
					// log.Println(msg)
					// save to file
					go func() {
						su, _ := url.Parse(fu)
						currentTimeFilePath := fmt.Sprintf("%s_%v", su.Hostname(), time.Now().Format("2006-01-02"))

						currentTimeFile := fmt.Sprintf("xss_%v_%v.txt", currentTimeFilePath, time.Now().UnixNano())

						savaPath := datedir + "/" + currentTimeFile
						// fmt.Println(savaPath, msg)
						if err := ioutil.WriteFile(savaPath, []byte(msg), 0777); err != nil {
							log.Println(err)
						}
					}()
				}

				jsHandleDialog := proto.PageHandleJavaScriptDialog{
					Accept:     true,
					PromptText: "webx2022",
				}
				err := jsHandleDialog.Call(page)
				if err != nil {
					// log.Println("....page handle dialog err:", err)
				}
			})()

			for _, fu := range fuzz_urls {
				// var response string
				// fmt.Println(fu)
				// 通过降速的方式解决页面加载较慢的情况【swagger xss】
				time.Sleep(time.Second * 1)

				err1 := page.Timeout(30 * time.Second).Navigate(fu)
				if err1 != nil {
					log.Println("[Page]Navigate Error:", fu, " err: ", err1)
				} else {
					// time.Sleep(time.Second * 1)
					peer := page.Timeout(30 * time.Second).WaitLoad()
					time.Sleep(time.Second * 1)
					if peer != nil {
						log.Println("[PageError Load]", fu, " |", peer)
					} else {
						checkResult, errJs1 := page.Timeout(10 * time.Second).Eval(CheckExpr)
						if errJs1 != nil {
							log.Println("[PageError Eval InitJS 1...]", errJs1)
						} else {
							tag := checkResult.Value.String()
							if tag != "<nil>" {
								// fmt.Println("[Vul]", fu, tag, checkResult)
								msg := fmt.Sprintf("%s\n\t%s\n", fu, tag)
								log.Println(msg)
								// save to file
								go func() {
									su, _ := url.Parse(fu)
									currentTimeFilePath := fmt.Sprintf("%s_%v", su.Hostname(), time.Now().Format("2006-01-02"))

									currentTimeFile := fmt.Sprintf("xss_%v_%v.txt", currentTimeFilePath, time.Now().UnixNano())

									savaPath := datedir + "/" + currentTimeFile
									// fmt.Println(savaPath, msg)
									if err := ioutil.WriteFile(savaPath, []byte(msg), 0777); err != nil {
										log.Println(err)
									}
								}()
								break
							}
						}

					}
				}

			}

			page.Close()
			agentBrowser.Close()
			go xlauncher.Cleanup()
		}

		g.Run(goFunc)
	}
	wg.Wait()
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func ReadFileByLine(filepath string) ([]string, error) {
	var (
		urls  []string
		rferr error
	)
	fi, err := os.Open(filepath)
	if err != nil {
		rferr = err
		return urls, rferr
	}
	defer fi.Close()
	br := bufio.NewScanner(fi)

	for {
		if !br.Scan() {
			break //文件读完了,退出for
		}
		line := br.Text() //获取每一行
		urls = append(urls, line)
	}
	return urls, rferr
}

func DisruptedOrder(infos []string) {
	rand.Shuffle(len(infos), func(i, j int) {
		infos[i], infos[j] = infos[j], infos[i]
	})
}
