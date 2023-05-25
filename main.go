package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
"bytes"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/howeyc/gopass"
)

type Config struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Config   string `json:"config"`
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("cannot find user home directory:", err)
		return
	}
	configPath := filepath.Join(home, ".openvpn_autoconnect_config.json")

	var config Config
	if _, err := os.Stat(configPath); err == nil {
		f, err := os.Open(configPath)
		if err != nil {
			fmt.Println("cannot open config file:", err)
			return
		}
		defer f.Close()

		if err := json.NewDecoder(f).Decode(&config); err != nil {
			fmt.Println("cannot parse config file:", err)
			return
		}
	}

	if config.Username == "" {
		fmt.Print("Enter username: ")
		reader := bufio.NewReader(os.Stdin)
		config.Username, _ = reader.ReadString('\n')
		config.Username = config.Username[:len(config.Username)-1] // Remove trailing newline
	}

	if config.Config == "" {
		fmt.Print("Enter OpenVPN config path: ")
		reader := bufio.NewReader(os.Stdin)
		config.Config, _ = reader.ReadString('\n')
		config.Config = config.Config[:len(config.Config)-1] // Remove trailing newline
	}

	fmt.Print("Enter your 4-digit key: ")
	userKey, err := gopass.GetPasswdMasked()
	if err != nil {
		fmt.Println("cannot read user key:", err)
		return
	}

	keyMaterial := getMacAddress() + getHostName() + string(userKey)
	key := sha256.Sum256([]byte(keyMaterial))

	var password string
	if config.Password != "" {
		passwordBytes, err := base64.StdEncoding.DecodeString(config.Password)
		if err != nil {
			fmt.Println("cannot decode password:", err)
			return
		}
		password, err = decrypt(key[:], passwordBytes)
		if err != nil {
			fmt.Println("cannot decrypt password:", err)
			return
		}
	} else {
		fmt.Print("Enter password: ")
		passwordBytes, err := terminal.ReadPassword(0)
		if err != nil {
			fmt.Println("cannot read password:", err)
			return
		}
		password = string(passwordBytes)
		encryptedPassword, err := encrypt(key[:], password)
		if err != nil {
			fmt.Println("cannot encrypt password:", err)
			return
		}
		config.Password = base64.StdEncoding.EncodeToString(encryptedPassword)
	}

	fmt.Print("Enter OTP: ")
	otp, err := terminal.ReadPassword(0)
	if err != nil {
		fmt.Println("cannot read OTP:", err)
		return
	}
	password += string(otp)

	cmd := exec.Command("openvpn3", "session-start", "--config", config.Config)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Println("cannot get stdin pipe:", err)
		return
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, config.Username+"\n")
		io.WriteString(stdin, password+"\n")
	}()

	err = cmd.Run()
	if err != nil {
		fmt.Println("command failed:", err)
		return
	}

	f, err := os.Create(configPath)
	if err != nil {
		fmt.Println("cannot create config file:", err)
		return
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(&config); err != nil {
		fmt.Println("cannot write config file:", err)
		return
	}
}

func getMacAddress() string {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
				// Don't use random as we have a real address
				return i.HardwareAddr.String()
			}
		}
	}
	return "00:00:00:00:00:00"
}

func getHostName() string {
	host, err := os.Hostname()
	if err != nil {
		fmt.Println("cannot get hostname:", err)
		return ""
	}
	return host
}

func encrypt(key []byte, plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return ciphertext, nil
}

func decrypt(key, ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv, ciphertext := ciphertext[:aes.BlockSize], ciphertext[aes.BlockSize:]

	cipher.NewCFBDecrypter(block, iv).XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
