// PCRE Matcher
// Don Franke// This utility cross-references a list of PCREs against a list of URLs.
// The goal is to get a list of potentially-malicious URLs that were
//   visited by employees.

//  The list of PCRE's can be obtained from open source intel
//  The list of URLs can be obtained fom proxy logs or other sources

// usage: ./pcrematcher
//           -u [url filename]
//           -p [pcre filename]
//           -e [exception list filename]
//           -se [show exemptions (Y/N)]

package main

import (
	"flag"
	"fmt"
	"github.com/glenn-brown/golang-pkg-pcre/src/pkg/pcre"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
)

var rawpcres []string
var validpcres []string
var rawurls []string
var validurls []string
var exemptions []string
var l string

type Result struct {
	url        string
	pcrestring string
	action     string
}

// generic error handler
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	l = "0"

	// 1. get command-line arguments
	pcrefile := flag.String("p", "", "Name of PCRE File")
	urlsfile := flag.String("u", "", "Name of URLs File")
	exfile := flag.String("e", "", "Name of exemptions File")
	showexempt := flag.String("se", "", "Show exempt URLs [Y/N]")
	flag.Parse()

	// make sure all flags are provided by user
	if *pcrefile == "" || *urlsfile == "" || *exfile == "" || *showexempt == "" {
		log.Fatal("EXECUTION HALTED: Not enough arguments supplied\n\n" + showUsage())
	}
	log.Print("Started")

	fmt.Println(*showexempt == "Y")

	// 2. load PCREs into memory
	loadPCREs(*pcrefile)

	// 3. load URLs into memory
	loadURLs(*urlsfile)

	// 4. load exemptions into memory
	if *exfile != "" {
		loadexemptions(*exfile)
	}

	// 5. compare urls against pcres
	preexemptresults := findMatches()

	// 6. compare results against exemptions
	postexemptresults := findExemptions(preexemptresults)
	//postexemptresults := preexemptresults
	//fmt.Print(len(postexemptresults))

	// 7. iterate and print results
	fmt.Println("\n\"ACTION\",\"URL\",\"PCRE\"")

	for _, item := range postexemptresults {
		// only display exempt URLs if user requested it
		if (*showexempt == "Y" && item.action == "EXEMPT") || item.action != "EXEMPT" {
			fmt.Printf("\"%s\",\"%s\",\"%s\"\n", item.action, item.url, item.pcrestring)
		}
	}
}

// match URL list against PCRE list
func findMatches() []Result {
	// local variables
	i := 0
	r := Result{}   // empty result object
	var r2 []Result // array of result objects
	j := len(validurls)

	fmt.Print("\tCompleted: ")
	// iterate urls
	for _, url := range validurls {
		// iterate pcres
		k := 0
		for _, p := range validpcres {
			//_ = "breakpoint"
			//ismatch, err := regexp.MatchString(pcres, url)
			//_ = p
			//_ = url
			//fmt.Printf("%d -- [[%s]] %s\n",k,url,p)
			k++
			m := pcre.MustCompile(p, 0).MatcherString(url, 0)

			if m.Matches() {
				// add result to result array
				r.url = url
				r.pcrestring = p
				r.action = "FOUND"
				r2 = append(r2, r)
			}
		}

		displayCounter(i,j)
		i++
		
	}
	return r2 // returning list of matching URLs-PCREs
}

// iterate results and identify exemptions
func findExemptions(inr []Result) []Result {
	i := 0
	r := Result{}   // empty result object
	var r2 []Result // array of result objects
	var action string

	// iterate urls
	for _, rs := range inr {
		action = "FOUND"
		// iterate exemption regexes
		for _, ex := range exemptions {
			if(ex!="") {
				exr, e := regexp.MatchString(ex, rs.url)
				if exr {
					_ = "breakpoint"
					//fmt.Print("\nEXEMPT\n")
					action = "EXEMPT"
					break
				}
				check(e)
			}
		}
		r = Result{rs.url, rs.pcrestring, action}
		r2 = append(r2, r)
		i++
	}
	return r2
}

// load PCREs into memory
func loadPCREs(pf string) {
	// local variables
	i := 1
	j := 1

	// load pcre file into memory
	dat, err := ioutil.ReadFile(pf)
	check(err)
	rawpcres = strings.Split(string(dat), "\n")

	// create comments regex pattern
	comments := regexp.MustCompile(`#`)

	// iterate raw pcres
	for _, item := range rawpcres {
		// remove comments
		iscomment := comments.MatchString(item)
		if !iscomment && len(item) > 0 {
			// extract regex from string
			findtab := strings.Index(item, "\t")
			if findtab > 0 {
				item = item[0:findtab]
			}
			// validate regex
			testr, err := pcre.Compile(item, 0)
			// dereference variable
			_ = testr
			if err != nil {
				fmt.Println(err)
				fmt.Printf("INVALID: %s\n", item)

				i++
			} else {
				validpcres = append(validpcres, item)
			}
		}
		j++
	}
	fmt.Printf("\tPCREs loaded: %d ", j)
	fmt.Printf("(%d considered invalid)\n", i)
}

// load urls (such as from proxy logs) into memory
func loadURLs(uf string) {
	// local variables
	i := 1

	// load url file into memory
	dat, err := ioutil.ReadFile(uf)
	check(err)
	rawurls = strings.Split(string(dat), "\n")

	// create comments regex pattern
	var comments = regexp.MustCompile(`#`)

	// iterate url list
	for _, item := range rawurls {
		// exclude comments
		iscomment := comments.MatchString(item)

		if !iscomment && len(item) > 0 && i > 1 {
			item = strings.Trim(item, "\"")
			validurls = append(validurls, item)
		}
		i++
	}
	fmt.Printf("\tURLs loaded: %d\n", i)
}

// load list of domains that are whitelisted
func loadexemptions(ef string) {
	dat, err := ioutil.ReadFile(ef)
	check(err)
	exemptions = strings.Split(string(dat), "\n")
	fmt.Printf("\tExemptions loaded: %d\n", len(exemptions))
}

func showUsage() string {
	var message string
	message = "\t-p = path/file of PCRE file\n"
	message += "\t-u = path/file of URL file\n"
	message += "\t-e = path/file of exemptions file\n"
	message += "\t-se = indicate whether or not to show exempt URLs in results [Y/N]\n\n"
	return message
}
func displayCounter(i int, j int) {
	var g string
	var pct float64

	// keep user updated on progress
	if i%1000 == 0 {
		pct = float64(i) / float64(j) * 100
		f := strconv.FormatFloat(pct, 'f', -1, 64)
		if len(f) > 6 {
			g = f[:strings.Index(f, ".")] // string version of integer version of percentage
		} else {
			g = f
		}
		// g is the string version of integer version of percentage
		if l != g {
			fmt.Printf("%s", g)
			fmt.Print("%...")
		}
		l = g
	}
	
}