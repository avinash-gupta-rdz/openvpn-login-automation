# OpenVPN Login Automation

This repository contains a Go program that streamlines the OpenVPN login process in Ubuntu by automating the provision of the username, password, and a time-based one-time password (TOTP). It remembers user configuration, including the username, password, config-path, and the shared secret for TOTP, and securely stores these details.

This Go script improves user experience and security by encrypting the password and OTP secret before storage and decrypting them during retrieval. A unique key derived from the device's MAC address, hostname, and a user-provided 4-digit key is used for this encryption/decryption process.

## Dependencies

This project uses the following Go dependencies:

- [gopass](https://github.com/howeyc/gopass) for secure password input.
<!-- - [otp/totp](https://github.com/pquerna/otp/totp) for generating TOTPs. -->
- Crypto libraries from Go's standard library for encryption/decryption.

To install the dependencies, use the `go get` command:

```bash
go get github.com/howeyc/gopass
```

## How to Run

1. Clone the repository:
    ```bash
    git clone https://github.com/username/openvpn-login-automation.git
    ```
2. Change into the directory:
    ```bash
    cd openvpn-login-automation
    ```
3. Run the Go script:
    ```bash
    go run main.go
    ```

Remember to replace `username` with your actual GitHub username.

## Further Reading

For a more detailed understanding of the code and the concepts involved, refer to our [blog post](https://yourblog.com/post-link) that traces the journey of automating OpenVPN login in Ubuntu using Go.

## Next Steps
 - Intigrate totp to automate authenticator codes
## Contributing

Your contributions are welcome! Feel free to fork the project and submit pull requests.

