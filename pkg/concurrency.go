package main

// 并发限制

type Glimit struct {
	n int
	c chan struct{}
}

// 初始化Glimit struct
func NewGlimit(n int) *Glimit {
	return &Glimit{
		n: n,
		c: make(chan struct{}, n),
	}
}

// 通过goroutine运行f函数，限制并发
func (g *Glimit) Run(f func()) {
	g.c <- struct{}{}
	go func() {
		f()
		<-g.c
	}()
}

