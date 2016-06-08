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
var exceptions[] string

func main() {
    fmt.Println("Running...")
    
    // get command-line arguments
    pcrefile := flag.String("p", "", "Name of PCRE File")
    urlsfile := flag.String("u", "", "Name of URLs File")
    exfile := flag.String("e", "", "Name of Exceptions File")

    // get arguments
    flag.Parse()
    //fmt.Println(*pcrefile)
    //fmt.Println(*urlsfile)
    //fmt.Println(*exfile)
    
    // open pcre file
    loadPCREs(*pcrefile)
    loadURLs(*urlsfile)
    if(*exfile!="") {
        loadExceptions(*exfile)
    }
    compare()
}

func compare() {    
    i := 0
    var action string

    fmt.Println("\"URL ID\",\"ACTION\",\"PCRE\",\"URL\"")
    
    // iterate urls
    for _, url := range validurls {
        // iterate pcres
        for _, pcre := range validpcres {
            ismatch,err := regexp.MatchString(pcre,url)         
            check(err)

            if(ismatch) {
                // make sure is not in exception list
                for _, ex := range exceptions {
                     exr,_ := regexp.MatchString(ex,url)  
                     if(exr) {
                        action = "SKIPPED"
                    } else {
                        action = "FOUND"
                        
                    } 
                    fmt.Printf("\"%d\",\"%s\",\"%s\",\"%s\"\n",i,action,pcre,url)
                }
            }
        }
        i++
    }
}

func loadPCREs(pf string) {
    // local variables
    i := 1
    j := 1

    // load pcre file into memory
    dat, err := ioutil.ReadFile(pf)
    check(err)
    rawpcres = strings.Split(string(dat),"\n")
    
    // create comments regex pattern
    comments := regexp.MustCompile(`#`)
    
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
        j++      
    }
    fmt.Printf("\t%d PCREs loaded ",j)
    fmt.Printf("(%d considered invalid)\n",i)
}

// load urls (such as from proxy logs) into memory
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
    fmt.Printf("\t%d URLs loaded\n",i)

}

// load list of domains that are whitelisted
func loadExceptions(ef string) {
    dat, err := ioutil.ReadFile(ef)
    check(err)
    exceptions = strings.Split(string(dat),"\n")
        fmt.Printf("\t%d Exception(s) loaded\n",len(exceptions))

}