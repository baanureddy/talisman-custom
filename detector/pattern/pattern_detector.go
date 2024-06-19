package pattern

import (
	"fmt"
	"regexp"
	"sync"
	"talisman/detector/helpers"
	"talisman/detector/severity"
	"talisman/gitrepo"
	"talisman/talismanrc"

	log "github.com/sirupsen/logrus"
)

type PatternDetector struct {
	secretsPattern *PatternMatcher
}

var (
	detectorPatterns = []*severity.PatternSeverity{
		//{Pattern: regexp.MustCompile(`(?i)((.*)(password|passphrase|secret|key|pwd|pword|pass)(.*) *[:=>,][^,;\n]{8,})`), Severity: severity.SeverityConfiguration["PasswordPhrasePattern"]},
		{Pattern: regexp.MustCompile(`(?i)((.*)(password|passphrase|secret|pwd|pword)(.*) *[:=>,][^,;\n]{8,})`), Severity: severity.SeverityConfiguration["PasswordPhrasePattern"]},
		//{Pattern: regexp.MustCompile(`(?i)((:)(password|passphrase|secret|key|pwd|pword|pass)(.*) *[ ][^,;\n]{8,})`), Severity: severity.SeverityConfiguration["PasswordPhrasePattern"]},
		{Pattern: regexp.MustCompile(`(?i)((:)(password|passphrase|secret|pwd|pword)(.*) *[ ][^,;\n]{8,})`), Severity: severity.SeverityConfiguration["PasswordPhrasePattern"]},
		{Pattern: regexp.MustCompile(`(?i)(['"_]?pw['"]? *[:=][^,;\n]{8,})`), Severity: severity.SeverityConfiguration["PasswordPhrasePattern"]},
		{Pattern: regexp.MustCompile(`(?i)(<ConsumerKey>\S*</ConsumerKey>)`), Severity: severity.SeverityConfiguration["ConsumerKeyPattern"]},
		{Pattern: regexp.MustCompile(`(?i)(<ConsumerSecret>\S*</ConsumerSecret>)`), Severity: severity.SeverityConfiguration["ConsumerSecretParrern"]},
		{Pattern: regexp.MustCompile(`(?i)(AWS[ \w]+key[ \w]+[:=])`), Severity: severity.SeverityConfiguration["AWSKeyPattern"]},
		{Pattern: regexp.MustCompile(`(?i)(AWS[ \w]+secret[ \w]+[:=])`), Severity: severity.SeverityConfiguration["AWSSecretPattern"]},
		{Pattern: regexp.MustCompile(`(?s)(BEGIN RSA PRIVATE KEY.*END RSA PRIVATE KEY)`), Severity: severity.SeverityConfiguration["RSAKeyPattern"]},
		{Pattern: regexp.MustCompile(`(?i)(?:github|gh|pat|token)[^\.].{0,40}[ =:'"]+([a-f0-9]{40})\b`), Severity: severity.SeverityConfiguration["Github"]},
		{Pattern: regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b`), Severity: severity.SeverityConfiguration["Github"]},
		{Pattern: regexp.MustCompile(`\b(glc_[A-Za-z0-9+\/]{50,150}\={0,2})`), Severity: severity.SeverityConfiguration["Graphana"]},
		{Pattern: regexp.MustCompile(`(xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34})`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(xoxb-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9-]*)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(xoxe.xox[bp]-\d-[A-Z0-9]{163,166})`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(xoxe-\d-[A-Z0-9]{146})`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(xoxb-[0-9]{8,14}\-[a-zA-Z0-9]{18,26})`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(xox[os]-\d+-\d+-\d+-[a-fA-F\d]+)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48})`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48})`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(https?:\/\/)?hooks.slack.com\/(services|workflows)\/[A-Za-z0-9+\/]{43,46}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:adafruit)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Adobe"]},
		{Pattern: regexp.MustCompile(`(?i)(?:adobe)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Adobe"]},
		{Pattern: regexp.MustCompile(`(?i)(?:airtable)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{17})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Airtable"]},
		{Pattern: regexp.MustCompile(`(?i)\b((LTAI)(?i)[a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Alibaba"]},
		{Pattern: regexp.MustCompile(`(?i)\b((p8e-)(?i)[a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:airtable)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{17})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:algolia)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b((LTAI)(?i)[a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:alibaba)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:atlassian|confluence|jira)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b((?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.acc[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:beamer)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(b_[a-z0-9=_\-]{44})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:bittrex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:bittrex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(CLOJARS_)[a-z0-9]{60}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:cloudflare)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:cloudflare)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{37})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:codecov)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:coinbase)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:confluent)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:confluent)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:contentful)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{43})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(dapi[a-h0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:datadog)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:dnkey)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(doo_v1_[a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(dop_v1_[a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(dor_v1_[a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9]{18})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(dp\.pt\.)(?i)[a-z0-9]{43}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:droneci)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{15})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(sl\.[a-z0-9\-=_]{135})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`duffel_(test|live)_(?i)[a-z0-9_\-=]{43}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`\bEZAK(?i)[a-z0-9]{54}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`\bEZTK(?i)[a-z0-9]{54}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:etsy)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(EAA[MC][a-z0-9]{20,})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:facebook)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:fastly)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:finicity)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:finicity)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:finnhub)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:flickr)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{12}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`FLWPUBK_TEST-(?i)[a-h0-9]{32}-X`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{32}-X`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`fio-u-(?i)[a-z0-9\-_=]{64}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:freshbooks)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:key|api|token|secret|client|passwd|password|auth|access|pass)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-z\-_.=]{10,150})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(ghu|ghs)_[0-9a-zA-Z]{36}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{82}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`ghr_[0-9a-zA-Z]{36}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`glpat-[0-9a-zA-Z\-\_]{20}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`glptt-[0-9a-f]{40}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`GR1348941[0-9a-zA-Z\-\_]{20}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:gitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:gocardless)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(live_(?i)[a-z0-9\-_=]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,2})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,2})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`((?:pat|sat)\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20})`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:administrator_login_password|password)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}("[a-z0-9=_\-]{8,20}")(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:heroku)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:hubspot)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(ico-[a-zA-Z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:intercom)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{60})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(s-s4t2(?:ud|af)-[abcdef0123456789]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:jfrog|artifactory|bintray|xray)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{73})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:jfrog|artifactory|bintray|xray)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["jwt"]},
		{Pattern: regexp.MustCompile(`\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\/\\_+\-\r\n]{40,}={0,2}`), Severity: severity.SeverityConfiguration["jwt"]},
		{Pattern: regexp.MustCompile(`(?i)(?:kraken)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9\/=_\+\-]{80,90})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:kucoin)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:kucoin)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:launchdarkly)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:linear)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:linkedin|linked-in)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{14})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:linkedin|linked-in)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:lob)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}((live|test)_[a-f0-9]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:lob)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}((test|live)_pub_[a-f0-9]{31})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:MailchimpSDK.initialize|mailchimp)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32}-us\d\d)(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(key-[a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(pubkey-[a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:mapbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(pk\.[a-z0-9]{60}\.[a-z0-9]{22})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:mattermost)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{26})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:messagebird|message-bird|message_bird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{25})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:messagebird|message-bird|message_bird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:netlify)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{40,46})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(NRJS-[a-f0-9]{19})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(NRII-[a-z0-9-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(NRAK-[a-z0-9]{27})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(npm_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:nytimes|new-york-times,|newyorktimes)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:okta)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{42})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(pscale_tkn_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(pscale_oauth_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(pscale_pw_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(pnu_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-----[\s\S-]*KEY( BLOCK)?----`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(pul-[a-f0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:rapidapi)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{50})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(rdme_[a-z0-9]{70})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(rubygems_[a-f0-9]{48})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`\b(tk-us-[a-zA-Z0-9-_]{48})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:sendbird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:sendbird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:sentry)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(shippo_(live|test)_[a-f0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`shpca_[a-fA-F0-9]{32}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`shppa_[a-fA-F0-9]{32}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(http(?:s??):\/\/)([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:snyk_token|snyk_key|snyk_api_token|snyk_api_key|snyk_oauth_token)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b((EAAA|sq0atp-)[0-9A-Za-z\-_]{22,60})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:squarespace)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b((sk|rk)_(test|live|prod)_[0-9a-z]{10,99})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i:(?:sumo)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3})(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(su[a-zA-Z0-9]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:sumo)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i:(?:telegr)(?:[0-9a-z\(-_\t .\\]{0,40})(?:[\s|']|[\s|"]){0,3})(?:=|\|\|:|<=|=>|:|\?=|\()(?:'|\"|\s|=|\x60){0,5}([0-9]{5,16}:A[a-z0-9_\-]{34})(?:['|\"|\n|\r|\s|\x60|;|\\]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:travis)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{22})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:twitch)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{45})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{25})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{50})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:typeform)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(tfp_[a-z0-9\-_\.=]{59})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(hvb\.[a-z0-9_-]{138,212})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)\b(hvs\.[a-z0-9_-]{90,100})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(AQVN[A-Za-z0-9_\-]{35,38})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}(YC[a-zA-Z0-9_\-]{38})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`(?i)(?:zendesk)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`), Severity: severity.SeverityConfiguration["Slack"]},
		{Pattern: regexp.MustCompile(`\b(mongodb(\+srv)?://[\S]{3,50}:([\S]{3,88})@[-.%\w\/:]+)\b`), Severity: severity.SeverityConfiguration["Mongo"]},
		{Pattern: regexp.MustCompile(`(?i)(%s).{0,20}([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`), Severity: severity.SeverityConfiguration["Azure"]},
		{Pattern: regexp.MustCompile(`\b(dckr_pat_[a-zA-Z0-9_-]{27})(?:[^a-zA-Z0-9_-]|\z)`), Severity: severity.SeverityConfiguration["Docker"]},
		{Pattern: regexp.MustCompile(`(npm_[0-9a-zA-Z]{36})`), Severity: severity.SeverityConfiguration["npm"]},
		{Pattern: regexp.MustCompile(`di[s]{1,2}://[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]+\b`), Severity: severity.SeverityConfiguration["redis"]},
	}
)

type match struct {
	name       gitrepo.FileName
	path       gitrepo.FilePath
	commits    []string
	detections []DetectionsWithSeverity
}

// Test tests the contents of the Additions to ensure that they don't look suspicious
func (detector PatternDetector) Test(comparator helpers.ChecksumCompare, currentAdditions []gitrepo.Addition, ignoreConfig *talismanrc.TalismanRC, result *helpers.DetectionResults, additionCompletionCallback func()) {
	matches := make(chan match, 512)
	ignoredFilePaths := make(chan gitrepo.FilePath, 512)
	waitGroup := &sync.WaitGroup{}
	waitGroup.Add(len(currentAdditions))
	for _, addition := range currentAdditions {
		go func(addition gitrepo.Addition) {
			defer waitGroup.Done()
			defer additionCompletionCallback()
			if ignoreConfig.Deny(addition, "filecontent") || comparator.IsScanNotRequired(addition) {
				ignoredFilePaths <- addition.Path
				return
			}
			detections := detector.secretsPattern.check(ignoreConfig.FilterAllowedPatternsFromAddition(addition), ignoreConfig.Threshold)
			matches <- match{name: addition.Name, path: addition.Path, detections: detections, commits: addition.Commits}
		}(addition)
	}
	go func() {
		waitGroup.Wait()
		close(matches)
		close(ignoredFilePaths)
	}()
	for ignoredChanHasMore, matchChanHasMore := true, true; ignoredChanHasMore || matchChanHasMore; {
		select {
		case match, hasMore := <-matches:
			if !hasMore {
				matchChanHasMore = false
				continue
			}
			detector.processMatch(match, result, ignoreConfig.Threshold)
		case ignore, hasMore := <-ignoredFilePaths:
			if !hasMore {
				ignoredChanHasMore = false
				continue
			}
			detector.processIgnore(ignore, result)
		}
	}
}

func (detector PatternDetector) processIgnore(ignoredFilePath gitrepo.FilePath, result *helpers.DetectionResults) {
	log.WithFields(log.Fields{
		"filePath": ignoredFilePath,
	}).Info("Ignoring addition as it was specified to be ignored.")
	result.Ignore(ignoredFilePath, "filecontent")
}

func (detector PatternDetector) processMatch(match match, result *helpers.DetectionResults, threshold severity.Severity) {
	for _, detectionWithSeverity := range match.detections {
		for _, detection := range detectionWithSeverity.detections {
			if detection != "" {
				if string(match.name) == talismanrc.DefaultRCFileName || !detectionWithSeverity.severity.ExceedsThreshold(threshold) {
					log.WithFields(log.Fields{
						"filePath": match.name,
						"pattern":  detection,
					}).Warn("Warning file as it matched pattern.")
					result.Warn(match.path, "filecontent", fmt.Sprintf("Potential secret pattern : %s", detection), match.commits, detectionWithSeverity.severity)
				} else {
					log.WithFields(log.Fields{
						"filePath": match.name,
						"pattern":  detection,
					}).Info("Failing file as it matched pattern.")
					result.Fail(match.path, "filecontent", fmt.Sprintf("Potential secret pattern : %s", detection), match.commits, detectionWithSeverity.severity)
				}
			}
		}
	}
}

// NewPatternDetector returns a PatternDetector that tests Additions against the pre-configured patterns
func NewPatternDetector(custom []talismanrc.PatternString) *PatternDetector {
	matcher := NewPatternMatcher(detectorPatterns)
	for _, pattern := range custom {
		matcher.add(pattern)
	}
	return &PatternDetector{matcher}
}
