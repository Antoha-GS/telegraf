package wireguard

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type ConfigParser struct {
	// Config root directory. Typically, /etc/wireguard
	root string
	// deviceName => PublicKey => tagName => tagValue
	extraTags map[string]map[string]map[string]string
}

func (p *ConfigParser) Parse() error {
	p.extraTags = make(map[string]map[string]map[string]string)
	return filepath.Walk(p.root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".conf") {
			name := info.Name()
			device := name[0 : len(name)-5]
			return p.parseFile(device, path)
		}
		return nil
	})
}

func (p *ConfigParser) parseFile(device string, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	//goland:noinspection GoUnhandledErrorResult
	defer file.Close()

	curKey := ""
	curTags := make(map[string]string)
	p.extraTags[device] = make(map[string]map[string]string)

	tagRegex := regexp.MustCompile("#+\\s*tag:\\s*(\\w+)\\s*=\\s*(.+)")
	publicKeyRegex := regexp.MustCompile("PublicKey\\s*=\\s*(.+)")

	lineNum := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[Peer]") {
			if len(curKey) != 0 && len(curTags) > 0 {
				p.extraTags[device][curKey] = curTags
				curKey = ""
				curTags = make(map[string]string)
			}
		} else {
			if match := tagRegex.FindStringSubmatch(line); len(match) == 3 {
				curTags[match[1]] = match[2]
			}
			if match := publicKeyRegex.FindStringSubmatch(line); len(match) == 2 {
				curKey = match[1]
			}
		}
	}
	if len(curKey) != 0 && len(curTags) > 0 {
		p.extraTags[device][curKey] = curTags
		curKey = ""
		curTags = make(map[string]string)
	}
	return scanner.Err()
}
