package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-github/v45/github"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var githubClient *github.Client

func init() {
	accessToken, loaded := os.LookupEnv("ACCESS_TOKEN")
	if !loaded {
		githubClient = github.NewClient(nil)
		return
	}
	transport := &github.BasicAuthTransport{
		Username: accessToken,
	}
	githubClient = github.NewClient(transport.Client())
}

// Get ext https://raw.githubusercontent.com/iamkuper/amnezia-discord-config/refs/heads/main/configs/all.subnets.txt
func include(dataMap map[string][]*net.IPNet) ([]string, error) {
	/* 	response, err := http.Get(downloadURL)
	   	if err != nil {
	   		return err
	   	}
	   	defer response.Body.Close() */
	var includedCodes []string
	files, err := os.ReadDir("./data")
	for _, file := range files {
		read, err := os.Open("./data/" + file.Name())
		if err != nil {
			return nil, err
		}
		defer read.Close()

		code := strings.TrimSuffix(file.Name(), ".txt")
		includedCodes = append(includedCodes, code)

		scanner := bufio.NewScanner(read)
		for scanner.Scan() {
			line := scanner.Text()
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				return nil, err
			}
			dataMap[code] = append(dataMap[code], ipNet)
		}
	}
	return includedCodes, err
}

// Fetch ip data release info from source repos
func fetch(from string) (*github.RepositoryRelease, error) {
	fixedRelease := os.Getenv("FIXED_RELEASE")
	names := strings.SplitN(from, "/", 2)
	if fixedRelease != "" {
		latestRelease, _, err := githubClient.Repositories.GetReleaseByTag(context.Background(), names[0], names[1], fixedRelease)
		if err != nil {
			return nil, err
		}
		return latestRelease, err
	} else {
		latestRelease, _, err := githubClient.Repositories.GetLatestRelease(context.Background(), names[0], names[1])
		if err != nil {
			return nil, err
		}
		return latestRelease, err
	}
}

func get(downloadURL *string) ([]byte, error) {
	log.Info("download ", *downloadURL)
	response, err := http.Get(*downloadURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func download(release *github.RepositoryRelease) ([]byte, error) {
	geoipAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "Country.mmdb"
	})
	if geoipAsset == nil {
		return nil, E.New("Country.mmdb not found in upstream release ", release.Name)
	}
	return get(geoipAsset.BrowserDownloadURL)
}

func parse(binary []byte) (metadata maxminddb.Metadata, countryMap map[string][]*net.IPNet, err error) {
	database, err := maxminddb.FromBytes(binary)
	if err != nil {
		return
	}
	metadata = database.Metadata
	networks := database.Networks(maxminddb.SkipAliasedNetworks)
	countryMap = make(map[string][]*net.IPNet)
	var country geoip2.Enterprise
	var ipNet *net.IPNet
	for networks.Next() {
		ipNet, err = networks.Network(&country)
		if err != nil {
			return
		}
		// idk why
		code := strings.ToLower(country.RegisteredCountry.IsoCode)
		countryMap[code] = append(countryMap[code], ipNet)
	}
	err = networks.Err()
	return
}

func newWriter(metadata maxminddb.Metadata, codes []string) (*mmdbwriter.Tree, error) {
	return mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "sing-geoip",
		Languages:               codes,
		IPVersion:               int(metadata.IPVersion),
		RecordSize:              int(metadata.RecordSize),
		Inserter:                inserter.ReplaceWith,
		DisableIPv4Aliasing:     true,
		IncludeReservedNetworks: true,
	})
}

// Generate geoip.db file
func write(writer *mmdbwriter.Tree, dataMap map[string][]*net.IPNet, output string, codes []string) error {
	if len(codes) == 0 {
		codes = make([]string, 0, len(dataMap))
		for code := range dataMap {
			codes = append(codes, code)
		}
	}
	sort.Strings(codes)

	codeMap := make(map[string]bool)
	for _, code := range codes {
		codeMap[code] = true
	}
	for code, data := range dataMap {
		if !codeMap[code] {
			continue
		}
		for _, item := range data {
			err := writer.Insert(item, mmdbtype.String(code))
			if err != nil {
				return err
			}
		}
	}
	outputFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer outputFile.Close()
	_, err = writer.WriteTo(outputFile)
	return err
}

func release(source string, destination string, output string, ruleSetOutput string) error {
	sourceRelease, err := fetch(source)
	if err != nil {
		return err
	}

	destinationRelease, err := fetch(destination)
	if err != nil {
		log.Warn("missing destination latest release")
	} else {
		if os.Getenv("NO_SKIP") != "true" && strings.Contains(*destinationRelease.Name, *sourceRelease.Name) {
			log.Info("already latest")
			setActionOutput("skip", "true")
			return nil
		}
	}

	// Download ip data from repos release
	binary, err := download(sourceRelease)
	if err != nil {
		return err
	}

	// metaData ?? countryMap - list of counry codes with ip addresses
	metadata, countryMap, err := parse(binary)
	if err != nil {
		return err
	}

	// Впиливаемся тут
	includedCodes, err := include(countryMap)
	if err != nil {
		return err
	}

	// Get all Country codes
	allCodes := make([]string, 0, len(countryMap))
	for code := range countryMap {
		allCodes = append(allCodes, code)
	}
	allCodes = append(allCodes, includedCodes...)

	// Writting geoip.db file
	writer, err := newWriter(metadata, allCodes)
	if err != nil {
		return err
	}
	err = write(writer, countryMap, output, nil)
	if err != nil {
		return err
	}

	// Trancated variant
	writer, err = newWriter(metadata, []string{"ru", "nl", "de", "fr", "us"})
	if err != nil {
		return err
	}

	err = write(writer, countryMap, "geoip-truncated.db", append([]string{"ru", "nl", "de", "fr", "us"}, includedCodes...))
	if err != nil {
		return err
	}

	// Clear rule-set branch
	os.RemoveAll(ruleSetOutput)
	err = os.MkdirAll(ruleSetOutput, 0o755)
	if err != nil {
		return err
	}

	// Write rule-set
	for countryCode, ipNets := range countryMap {
		var headlessRule option.DefaultHeadlessRule
		headlessRule.IPCIDR = make([]string, 0, len(ipNets))
		for _, cidr := range ipNets {
			headlessRule.IPCIDR = append(headlessRule.IPCIDR, cidr.String())
		}
		var plainRuleSet option.PlainRuleSet
		plainRuleSet.Rules = []option.HeadlessRule{
			{
				Type:           C.RuleTypeDefault,
				DefaultOptions: headlessRule,
			},
		}
		srsPath, _ := filepath.Abs(filepath.Join(ruleSetOutput, "geoip-"+countryCode+".srs"))
		os.Stderr.WriteString("write " + srsPath + "\n")
		outputRuleSet, err := os.Create(srsPath)
		if err != nil {
			return err
		}
		defer outputRuleSet.Close()
		err = srs.Write(outputRuleSet, plainRuleSet)
		if err != nil {
			return err
		}
	}

	setActionOutput("tag", *sourceRelease.Name)
	return nil
}

func setActionOutput(name string, content string) {
	os.Stdout.WriteString("::set-output name=" + name + "::" + content + "\n")
}

func main() {
	err := release("Dreamacro/maxmind-geoip", "MYffffff/sing-geoip", "geoip.db", "rule-set")
	if err != nil {
		log.Fatal(err)
	}
}
