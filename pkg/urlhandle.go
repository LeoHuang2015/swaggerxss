package main

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
)

func IsUrl(u string) bool {
	re := regexp.MustCompile(`(http|ftp|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?`)
	result := re.FindAllStringSubmatch(u, -1)
	return result != nil
}

func InsertPathRandom(path string, insertinfo string, pathLen int) string {
	randIndex := rand.Intn(pathLen - 1)
	randIndex = randIndex + 1
	return path[:randIndex] + insertinfo + path[randIndex:]
}

func IsStatic(path string, staticsuffix []string) bool {
	staticFlag := false
	for _, suffix := range staticsuffix {
		if strings.HasSuffix(strings.ToLower(path), suffix) {
			staticFlag = true
			break
		}
	}
	return staticFlag
}

func IsBlack(url string, urlblacklist []string) bool {
	blackFlag := false
	for _, blackurl := range urlblacklist {
		if strings.HasPrefix(strings.ToLower(url), blackurl) {
			blackFlag = true
			break
		}
	}
	return blackFlag
}

type ScanUrl struct {
	Url          string
	FringerPrint string

	Scheme   string
	Host     string
	Hostname string
	Port     string
	Path     string
	Fragment string
	RawQuery string

	ParsedQuery     map[string][]string
	ParsedFragement map[string][]string
}

func (su *ScanUrl) Parse(urlline string) error {
	if IsUrl(urlline) {
		u, err := url.Parse(urlline)
		if err == nil {
			su.Url = urlline
			su.Scheme = u.Scheme
			su.Host = u.Host
			su.Hostname = u.Hostname()
			su.Port = u.Port()
			su.Path = u.Path
			su.RawQuery = u.RawQuery
			su.Fragment = u.Fragment
			su.ParsedQuery, _ = url.ParseQuery(su.RawQuery)
			su.ParsedFragement, _ = url.ParseQuery(su.Fragment)

			h := sha1.New()
			h.Write([]byte(urlline))
			bs := h.Sum(nil)
			su.FringerPrint = fmt.Sprintf("%x", bs)

			return nil
		}
		return err
	} else {
		return errors.New("非标准url格式")
	}

}

// 复制一份原始数据
func CopyParsedQeury(parsedquery map[string][]string) map[string][]string {
	tmpParsedQeury := make(map[string][]string)
	for queryKey, queyrValueArr := range parsedquery {
		cpy := make([]string, len(queyrValueArr))
		copy(cpy, queyrValueArr)
		tmpParsedQeury[queryKey] = cpy
	}
	return tmpParsedQeury
}

func ReplaceQuery(parsedquery map[string][]string, fuzzValues []string, mode string) []map[string][]string {
	var resultParsedQeuryArry []map[string][]string

	if mode == "add" || mode == "all" {
		// 遍历参数
		for queryKey, queyrValueArr := range parsedquery {
			//遍历 payload
			for _, fv := range fuzzValues {
				tmpParsedQeury1 := CopyParsedQeury(parsedquery)
				newvalueArr1 := make([]string, len(queyrValueArr))
				copy(newvalueArr1, queyrValueArr)
				tmp_value := newvalueArr1[0]
				newvalueArr1[0] = tmp_value + fv
				tmpParsedQeury1[queryKey] = newvalueArr1
				resultParsedQeuryArry = append(resultParsedQeuryArry, tmpParsedQeury1)
			}
		}
	}
	if mode == "replace" || mode == "all" {
		// 遍历参数
		for queryKey, queyrValueArr := range parsedquery {
			//遍历 payload
			for _, fv := range fuzzValues {
				tmpParsedQeury2 := CopyParsedQeury(parsedquery)
				newvalueArr2 := make([]string, len(queyrValueArr))
				copy(newvalueArr2, queyrValueArr)
				newvalueArr2[0] = fv
				tmpParsedQeury2[queryKey] = newvalueArr2
				resultParsedQeuryArry = append(resultParsedQeuryArry, tmpParsedQeury2)
			}
		}
	}

	return resultParsedQeuryArry
}

func UnParseQuery(parsedquery map[string][]string) (query string) {
	// query := ""
	for k, vs := range parsedquery {
		for _, v := range vs {
			if len(query) > 0 {
				query += fmt.Sprintf("&%s=%s", k, url.QueryEscape(v))
			} else {
				query += fmt.Sprintf("%s=%s", k, url.QueryEscape(v))
			}

			// query += fmt.Sprintf("%s=%s", k, v)
		}
	}
	return query
}
