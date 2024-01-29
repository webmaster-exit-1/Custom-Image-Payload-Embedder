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

## Development

### Prerequisites

- Ruby (version as specified by Metasploit)
- Metasploit Framework

### Setting Up the Development Environment

1. Fork and clone the repository.
2. Install the required Ruby version (use a Ruby version manager like `rbenv` or `rvm`).
3. Install dependencies: `bundle install`
4. Make changes to the module code as needed.

### Debugging and Testing

- Use `irb` or `pry` for interactive debugging.
- Write and run unit tests using the `rspec` framework.

## Contributing

Contributions to this project are welcome. Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes with descriptive commit messages.
4. Push your branch and submit a pull request.

## Author

Webmaster-Exit-1

## Disclaimer

I have not yet tested or finished this project. The first commit date is me just brainstorming.
This module is intended for educational and ethical testing purposes only. The author is not responsible for any misuse or damage caused by this module.
