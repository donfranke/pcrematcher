# PCRE Matcher
Matches a list of URLs against a list of PCREs, meant to detect visits to malicious sites. 

# Example
The regular expression 

hxxp:\/\/([^\.\/]+\.)+(edu|net|com|org)\/sync\/v\d{1,3}

Matches

hxxp://test.evaluationserver.com/sync/v1

Note: this is a fake site.


# Usage
```
./pcrematcher -u [url filename] -p [pcre filename]
```
# Requirements
Go
