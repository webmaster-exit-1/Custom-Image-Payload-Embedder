# Custom Image Payload Embedder

## Description

This Metasploit module embeds a Metasploit payload into an image file. It is designed to be used on Linux platforms and allows for the stealthy execution of payloads within an innocuous-looking image file.

## Features

- Embeds a Metasploit payload into an image file.
- Encrypts the payload with a randomly generated key using XOR encryption.
- Provides options to specify the image and payload paths.

## Installation

To use this module, you must have Metasploit Framework installed on your system. If you do not have it installed, you can download it from the following link:
[Metasploit Download](https://www.metasploit.com/download)

Once Metasploit is installed, follow these steps:

1. Clone this repository to your local machine.
2. Copy the module into the appropriate Metasploit directory (typically `~/.msf4/modules/exploits/`).
3. Start the Metasploit console and load the module.

## Usage

To use the module, you need to set the `IMAGE_PATH` and `PAYLOAD_PATH` options to point to your image file and payload file, respectively.

Example usage:

```ruby
msfconsole use exploit/custom_image_payload_embedder
set IMAGE_PATH /path/to/image.jpg
set PAYLOAD_PATH /path/to/payload.bin
exploit
```
