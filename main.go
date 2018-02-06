package main

import (
	"bytes"
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// Button is a Dash, from Amazon
type Button struct {
	Name     string
	URL      string
	Username string
	MAC      string
	Method   string
	Header   map[string]string
	Data     map[string]string
}

// Configuration is Network Interface and Buttons.
type Configuration struct {
	Buttons []Button
	NIC     string
}

func loadConfig() Configuration {
	file, _ := os.Open("conf.json")
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		log.Fatalln("Error Loading Configuration:", err)
	}
	log.Println("Loaded", len(configuration.Buttons), "Button(s):")
	for _, button := range configuration.Buttons {
		log.Printf("- Button: %v (%v): %v, [%v], [%v]", button.Name, button.MAC, button.URL, button.Header, button.Data)
	}
	return configuration
}

func main() {
	var configuration = loadConfig()
	log.Printf("Starting up on interface[%v]...", configuration.NIC)

	var filter = "arp and ("
	// Create a packet capture filter for the button's MAC addresses.
	for _, button := range configuration.Buttons {
		MAC, err := net.ParseMAC(button.MAC)
		if err != nil {
			log.Fatalf("Unable to parse MAC: %s (%s)\n", button.MAC, err)
		}
		if filter != "arp and (" {
			filter += " or "
		}
		filter += "(ether src host " + MAC.String() + ")"
	}
	filter += ")"
	capturePackages(configuration.NIC, filter, configuration.Buttons)
}

func capturePackages(NIC string, filter string, buttons []Button) {
	h, err := pcap.OpenLive(NIC, 65536, true, pcap.BlockForever)
	defer h.Close()
	if err != nil || h == nil {
		log.Fatalf("Error opening interface: %s\nPerhaps you need to run as root?\n", err)
	}

	if err = h.SetBPFFilter(filter); err != nil {
		log.Fatalf("Unable to set filter: %s %s\n", filter, err)
	}

	log.Println("Listening for Dash buttons...")
	packetSource := gopacket.NewPacketSource(h, h.LinkType())

	// Using a BPF filter to limit packets to only our buttons,
	// there is no need to capture anything besides MAC here.
	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		for _, button := range buttons {
			if strings.ToUpper(ethernetPacket.SrcMAC.String()) == strings.ToUpper(button.MAC) {
				log.Println("Button", button.Name, "was pressed.")
				go makeRequest(button.URL, button.Username, button.Method, button.Header, button.Data)
				break
			}
		}
	}
}

func makeRequest(url string, username string, method string, header map[string]string, data map[string]string) {
	var cmd *exec.Cmd
	if username != "" {
		// Adding digest auth to Go looked like hell. This was a lot easier.
		cmd = exec.Command("curl", "-u", username, "--digest", url)
		cmd.Stderr = cmd.Stdout
		output, err := cmd.Output()
		if err != nil {
			log.Println("Error Curling URL", url, "->", err)
		} else {
			log.Println("Curl Output:", string(output))
		}
	} else {
		var res *http.Response
		var err error

		client := &http.Client{}

		body, _ := json.Marshal(data)
		if body != nil {
			log.Printf("Sending data: %v", string(body))
		}

		req, err := http.NewRequest(method, url, bytes.NewReader(body))

		if header != nil {
			log.Println("Adding headers:")
			for key, value := range header {
				log.Println("    ", key, " -> ", value)
				req.Header.Set(key, value)
			}
		}
		req.Header.Set("Content-Type", "application/json")

		res, err = client.Do(req)

		if err != nil {
			log.Println("Error requesting URL", url, "->", err)
			return
		}

		defer func() {
			// This is how you win the game of `errcheck`.
			if err := res.Body.Close(); err != nil {
				log.Println("Failed to close HTTP response body:", err)
			}
		}()

		if output, err := ioutil.ReadAll(res.Body); err != nil {
			log.Println("Error requesting URL", url, "->", err)
		} else {
			log.Println("Result:", string(output))
		}
	}
}
