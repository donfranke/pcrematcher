# PCRE Matcher
Matches a list of URLs against a list of PCREs (Perl Compatible Regular Expressions), meant to detect visits to malicious sites. The PCREs can be maintained by you or provided by intel sources; the list of URLs come from your proxy logs; the list of exceptions is a list you maintain to eliminate false positive matches (not all the PCREs are perfect.)

# Input Files
* list of pcres
* list of urls
* list of exceptions (optional)

# Usage
```
./pcrematcher -u [url filename] -p [pcre filename] -e [exception list filename]
```
# Requirements
Go
