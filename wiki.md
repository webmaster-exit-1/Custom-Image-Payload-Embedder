# Custom-Image-Payload-Embedder

The `/Custom-Image-Payload-Embedder` repository contains a Metasploit module that allows users to embed a payload (e.g., Meterpreter shell) into an image file and generate a malicious HTML file. This functionality is particularly useful for penetration testers and security researchers who need to create stealthy payloads that can bypass antivirus detection.

The core functionality of the module is implemented in the `/Custom-Image-Payload-Embedder/lib` directory, which includes three main files: [`embedded_image_payload.rb`](/Custom-Image-Payload-Embedder/lib/embedded_image_payload.rb#L0), [`module.rb`](/Custom-Image-Payload-Embedder/lib/module.rb#L0), and [`payload.rb`](/Custom-Image-Payload-Embedder/lib/payload.rb#L0). These files provide a comprehensive set of methods for generating the payload, applying encryption, polymorphism, and heuristic obfuscation techniques to the payload, embedding the payload into an image file, and generating a malicious HTML file that, when loaded, will execute the embedded payload.

The [`EmbeddedImagePayload`](/Custom-Image-Payload-Embedder/lib/payload.rb#L9) module in [`embedded_image_payload.rb`](/Custom-Image-Payload-Embedder/lib/embedded_image_payload.rb#L0) is the main entry point for the functionality. It includes several Metasploit modules, such as [`Msf::Exploit::FILEFORMAT`](/Custom-Image-Payload-Embedder/lib/module.rb#L12), [`Msf::Exploit::EXE`](/Custom-Image-Payload-Embedder/lib/module.rb#L13), and [`Msf::Exploit::Remote::HttpServer::HTML`](/Custom-Image-Payload-Embedder/lib/module.rb#L14), which provide the necessary functionality for payload generation, file format exploitation, and web server hosting.

The module utilizes various techniques to generate a polymorphic payload, apply heuristic obfuscation methods, and embed the payload into an image file. These techniques include:

- Generating a random encryption key and applying XOR encryption to the payload using the [`generate_random_key()`](/Custom-Image-Payload-Embedder/lib/module.rb#L35) and [`xor_encrypt()`](/Custom-Image-Payload-Embedder/lib/module.rb#L39) methods.
- Applying polymorphic techniques to the payload, such as inserting NOP instructions, randomizing register usage, inserting junk code, and shuffling the order of instructions, using the [`generate_polymorphic_payload()`](/Custom-Image-Payload-Embedder/lib/module.rb#L44) method.
- Applying heuristic obfuscation techniques to the payload, including Base64 encoding, Zlib compression, AES-256-CBC encryption, and routine obfuscation, using the [`heuristic_technique()`](/Custom-Image-Payload-Embedder/lib/module.rb#L71) method.
- Embedding the final payload into the specified image file using the [`embed_payload_into_image()`](/Custom-Image-Payload-Embedder/lib/module.rb#L106) method and the [`Rex::Zip::Archive`](/Custom-Image-Payload-Embedder/lib/module.rb#L108) class.
- Generating a malicious HTML file that, when loaded, will execute the embedded payload by extracting it from the image and running it, using the [`generate_malicious_html()`](/Custom-Image-Payload-Embedder/lib/module.rb#L114) method.

The [`exploit()`](/Custom-Image-Payload-Embedder/lib/module.rb#L149) method in each of the three main files is the entry point that coordinates the overall functionality of the module, from payload generation to malicious HTML file creation.

[Payload Generation and Obfuscation](#payload-generation-and-obfuscation)
[Payload Embedding and Malicious HTML Generation](#payload-embedding-and-malicious-html-generation)

## Payload Generation and Obfuscation
References: `/Custom-Image-Payload-Embedder/lib`

The `/Custom-Image-Payload-Embedder/lib` directory contains the core functionality for generating a polymorphic payload, applying encryption and heuristic obfuscation techniques, and embedding the payload into an image file.

The [`generate_random_key()`](/Custom-Image-Payload-Embedder/lib/module.rb#L35) method generates a random encryption key using [`SecureRandom.random_bytes()`](/Custom-Image-Payload-Embedder/lib/module.rb#L36). This key is then used to apply XOR encryption to the payload in the [`xor_encrypt()`](/Custom-Image-Payload-Embedder/lib/module.rb#L39) method.

The [`generate_polymorphic_payload()`](/Custom-Image-Payload-Embedder/lib/module.rb#L44) method applies several techniques to create a polymorphic payload:

- Inserting a random number of NOP (No Operation) instructions at the beginning of the payload
- Randomizing the register usage in the payload
- Inserting random junk code at a random location in the payload
- Shuffling the order of the instructions in the payload, while maintaining the order of critical instructions

To further obfuscate the payload and evade antivirus detection, the [`heuristic_technique()`](/Custom-Image-Payload-Embedder/lib/module.rb#L71) method applies the following techniques:

- Encoding the payload using Base64
- Compressing the payload using Zlib
- Encrypting the compressed payload using AES-256-CBC with a randomly generated key and IV
- Obfuscating the decryption and decompression routines

The [`embed_payload_into_image()`](/Custom-Image-Payload-Embedder/lib/module.rb#L106) method uses the [`Rex::Zip::Archive`](/Custom-Image-Payload-Embedder/lib/module.rb#L108) class to embed the final payload into the specified image file.

## Payload Embedding and Malicious HTML Generation
References: `/Custom-Image-Payload-Embedder/lib`

The `/Custom-Image-Payload-Embedder/lib` directory contains the core functionality for embedding a payload into an image file and generating a malicious HTML file that, when loaded, will execute the embedded payload.

The [`EmbeddedImagePayload`](/Custom-Image-Payload-Embedder/lib/payload.rb#L9) module, defined in `/Custom-Image-Payload-Embedder/lib/embedded_image_payload.rb`, is the main entry point for this functionality. This module includes several Metasploit modules, such as [`Msf::Exploit::FILEFORMAT`](/Custom-Image-Payload-Embedder/lib/module.rb#L12), [`Msf::Exploit::EXE`](/Custom-Image-Payload-Embedder/lib/module.rb#L13), and [`Msf::Exploit::Remote::HttpServer::HTML`](/Custom-Image-Payload-Embedder/lib/module.rb#L14), which provide the necessary functionality for file format exploitation, executable generation, and HTTP server handling.

The module's [`exploit()`](/Custom-Image-Payload-Embedder/lib/module.rb#L149) method coordinates the overall process of payload generation, encryption, polymorphism, heuristic obfuscation, payload embedding, and malicious HTML file generation:

- The [`generate_random_key()`](/Custom-Image-Payload-Embedder/lib/module.rb#L35) method generates a random encryption key using [`SecureRandom.random_bytes()`](/Custom-Image-Payload-Embedder/lib/module.rb#L36).
- The [`xor_encrypt()`](/Custom-Image-Payload-Embedder/lib/module.rb#L39) method applies XOR encryption to the payload using the generated key.
- The [`generate_polymorphic_payload()`](/Custom-Image-Payload-Embedder/lib/module.rb#L44) method applies various polymorphic techniques to the payload, such as inserting NOP instructions, randomizing register usage, inserting junk code, and shuffling the order of instructions.
- The [`heuristic_technique()`](/Custom-Image-Payload-Embedder/lib/module.rb#L71) method applies several heuristic techniques to the payload to evade antivirus detection, including Base64 encoding, Zlib compression, AES-256-CBC encryption, and routine obfuscation.
- The [`embed_payload_into_image()`](/Custom-Image-Payload-Embedder/lib/module.rb#L106) method embeds the final payload into the specified image file using the [`Rex::Zip::Archive`](/Custom-Image-Payload-Embedder/lib/module.rb#L108) class.
- The [`generate_malicious_html()`](/Custom-Image-Payload-Embedder/lib/module.rb#L114) method generates a malicious HTML file that, when loaded, will execute the embedded payload by extracting it from the image and running it.

The `/Custom-Image-Payload-Embedder/lib/module.rb` and `/Custom-Image-Payload-Embedder/lib/payload.rb` files also contain similar [`MetasploitModule`](/Custom-Image-Payload-Embedder/lib/module.rb#L9) classes that provide the same core functionality as the [`EmbeddedImagePayload`](/Custom-Image-Payload-Embedder/lib/payload.rb#L9) module.

