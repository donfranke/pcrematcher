// This utility cross-references a list of PCREs against a list of URLs.
// The goal is to get a list of potentially-malicious URLs that were
//   visited by employees.

//  The list of PCRE's can be obtained from open source intel
//  The list of URLs can be obtained fom proxy logs or other sources

//   usage:  ./gomatch -u [url file path/name] -p [pcre file path/name]
package main

import (
    "fmt"
    "io/ioutil"
    "strings"
    "regexp"
    "flag"
)

func check(e error) {
    if e != nil {
        panic(e)
    }
}

var rawpcres[] string
var validpcres[] string
var rawurls[] string
var validurls[] string

func main() {
	fmt.Println("Running...")
	
	// get command-line arguments
	pcrefile := flag.String("p", "", "Name of PCRE File")
	urlsfile := flag.String("u", "", "Name of URLs File")

	// get arguments
	flag.Parse()
	fmt.Println(*pcrefile)
	fmt.Println(*urlsfile)
	
	// open pcre file
	loadPCREs(*pcrefile)
	loadURLs(*urlsfile)
	compare()
}

func compare() {	
	i := 0
	
	// iterate urls
	for _, url := range validurls {
		// iterate pcres
		for _, pcre := range validpcres {
			ismatch,err := regexp.MatchString(pcre,url)			
			check(err)

			if(ismatch) {
				fmt.Println("MATCH:", pcre, " --> ", url)
				fmt.Println("(dest_host=\""+url+"\" AND uri_path=\"" + url + "\"")

			}
		}
		if(i%500==0) {
			fmt.Println(i,"/",len(validurls)," URLS examined")
		}
		i++
	}
}

func loadPCREs(pf string) {
	// local variables
	i := 1

	// load pcre file into memory
	dat, err := ioutil.ReadFile(pf)
    check(err)
    rawpcres = strings.Split(string(dat),"\n")
    
    // create comments regex pattern
    var comments = regexp.MustCompile(`#`)
    
    // iterate raw pcres
    for _, item := range rawpcres {
    	// remove comments
    	iscomment := comments.MatchString(item)
    	if(!iscomment&&len(item)>0) {
    		// extract regex from string
    		findtab := strings.Index(item,"\t")
    		item = item[0:findtab]
    		// validate regex
    		testr,err := regexp.Compile(item)
    		// dereference variable
    		_ = testr
    		if(err!=nil) {
    			i++
    		} else {
    			validpcres = append(validpcres, item)
    		}
    	}    	
    }
    fmt.Println(i," PCREs considered invalid")
}

func loadURLs(uf string) {
	// local variables
	i := 1
	
	// load url file into memory
	dat, err := ioutil.ReadFile(uf)
    check(err)
    rawurls = strings.Split(string(dat),"\n")

    // create comments regex pattern
	var comments = regexp.MustCompile(`#`)
    
    // iterate url list
    for _, item := range rawurls {
    	// exclude comments
    	iscomment := comments.MatchString(item)

    	if(!iscomment&&len(item)>0&&i>1) {
    		item = strings.Trim(item,"\"")
    		validurls = append(validurls, item)
    	} 
    	i++   	
    }	
}