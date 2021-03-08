package main

/*
build with docker "$ docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:1.14 go build -v"

*/
import (
	"flag"

	step "github.com/denautonomepirat/steppingstone"
	log "github.com/sirupsen/logrus"
)

var app = &step.Config{}

func main() {

	pathToConf := flag.String("p", "./conf.yml", "Path to yaml config file")
	debug := flag.Bool("d", false, "set to true for debug")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
		log.Info("Setting loglevel to debug")
	}

	err := app.LoadConfig(pathToConf)
	if err != nil {
		log.Fatalln(err.Error())
	}
	app.Info()
	app.Run()
}
