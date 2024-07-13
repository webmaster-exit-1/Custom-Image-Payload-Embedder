<!--markdownlint-disable-->

<h1 align="center"><b><u>Custom Image Payload Embedder Module</u></b></h1>

### This <span class="underline-red">No-Click Payload</span> for Metasploit embeds a payload (e.g., Meterpreter shell) into a .jpeg, .jpg, .webp, .png, or .gif image and generates a malicious HTML file. When the image is viewed in a web browser, the HTML file is automatically loaded, triggering the execution of the embedded payload and potentially compromising the system.

**The Breakdown:**

*   _**No User Interaction:**_  The payload is executed without any action required from the victim, except for viewing the image in a browser.
*   _**HTML File as Trigger:**_ The HTML file acts as the trigger mechanism for the payload. It's automatically loaded when the image is viewed, making the attack seamless.
*   _**Potential Impact:**_ Every image online is now a potentail "payload".

Take note that all my code was created with the help pf LLM's or "AI". All of my code is a suggestion. Anything can be modified or made to execute better. Skill and imagination are all that limits us. <br>

* _Inspiration for this project was obtained by how [**__Canary Tokens__**](https://canarytokens.org/generate) operate_.

<h1><p align="center"><b>Happy Hacking</b></p></h1>

------

## Features

- **Steganography:** Hides the payload within an image file.
- **Encryption:** Encrypts the payload using XOR encryption with a random key.
- **Polymorphism:** Applies techniques to obfuscate the payload and evade antivirus detection.
- **Malicious HTML Generation:** Creates an HTML file that extracts and executes the embedded payload.
- **Metasploit Integration:**  Designed to work seamlessly with the Metasploit framework for handler setup and post-exploitation.

## Requirements

- **Ruby programming language (version 2.7 or higher)**
- **Metasploit framework:** Follow the installation instructions for your operating system from the official Metasploit website: [https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/webmaster-exit-1/Custom-Image-Payload-Embedder.git
   ```
   
2. Navigate to the project directory:

   ```sh
   cd embedded-image-payload
   ```

3. Install dependencies:
   ```rb
   bundle install
   ```

## Usage <br>
  1. Customize (Optional): <br>
    * Modify module.rb to adjust settings like image path and output path. <br>
    * Customize payload generation or obfuscation techniques in payload.rb if needed. <br>
  2. Generate Payload and HTML: <br>
    * Execute your Metasploit module (replace <your_module_filename.rb> with the actual filename): <br>
   ```rb
   ruby <your_module_filename.rb>
   ```
  3. Set Up Metasploit Handler: <br>
    * Open a new terminal and start msfconsole. <br>
    * Use the exploit/multi/handler module. <br>
    * Configure the handler to match the payload used in your module. <br>
    * Set LHOST (your IP) and LPORT. <br>
    * Start the handler with run. <br>
  4. Deliver and Execute: <br>
    * Transfer the generated malicious HTML file to the target machine. <br>
    * Open the HTML file in a web browser on the target. <br>

Example

   ```md
   # In your Metasploit module file (e.g., module.rb)
   # ... your module code ...

   def exploit
     # ... your exploit logic ...

     # Example payload configuration (adjust as needed)
     payload_data = generate_payload_exe
     key = generate_random_key(16)
     encrypted_payload = xor_encrypt(payload_data, key)
     polymorphic_payload = generate_polymorphic_payload(encrypted_payload)
     final_payload = heuristic_technique(polymorphic_payload)

     # ... rest of your exploit logic ...
   end
   ```
## Disclaimer
### This project is for educational and research purposes only. Using it for malicious activities is illegal and unethical. The authors are not responsible for any misuse or damage caused by this project. Use it responsibly and ethically.
