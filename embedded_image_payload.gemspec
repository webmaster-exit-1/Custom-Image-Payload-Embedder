Gem::Specification.new do |spec|
  spec.name         = 'embedded_image_payload'
  spec.version      = '1.0.0'
  spec.authors      = ['Webmaster-exit-1']
  spec.email        = ['echohellosuperuser@member.fsf.org']
  spec.summary      = 'Embedded Image Payload Module'
  # rubocop:todo Layout/LineLength
  spec.description  = 'A Metasploit module that embeds a payload into an image file and generates a malicious HTML file.'
  # rubocop:enable Layout/LineLength
  spec.homepage     = 'https://github.com/webmaster-exit-1/embedded-image-payload'
  spec.license      = 'GPL3'
  spec.files        = Dir['lib/**/*'] + ['README.md', 'LICENSE']
  spec.require_path = 'lib'
  spec.add_dependency 'metasploit-framework', '~> 6.0'
end
