# Encoding: ASCII-8BIT

require 'socket'

class LibNeptune
  # From https://docs.rocketsoftware.com/bundle/grv1653317862214_grv1653317862214/page/nhb1653316841876.html
  ERROR_CODES = {
    0 => 'UVE_NOERROR',
    14002 => 'UVE_ENOENT',
    14005 => 'UVE_EIO',
    14009 => 'UVE_EBADF',
    14012 => 'UVE_ENOMEM',
    14013 => 'UVE_EACCES',
    14022 => 'UVE_EINVAL',
    14023 => 'UVE_ENFILE',
    14024 => 'UVE_EMFILE',
    14028 => 'UVE_ENOSPC',
    14551 => 'UVE_NETUNREACH',
    22001 => 'UVE_BFN',
    22002 => 'UVE_BTS',
    20003 => 'UVE_IID',
    22004 => 'UVE_LRR',
    22005 => 'UVE_NFI',
    30001 => 'UVE_RNF',
    30002 => 'UVE_LCK',
    30095 => 'UVE_FIFS',
    30097 => 'UVE_SELFAIL',
    30098 => 'UVE_LOCKINVALID',
    30099 => 'UVE_SEQOPENED',
    30100 => 'UVE_HASHOPENED',
    30101 => 'UVE_SEEKFAILED',
    30103 => 'UVE_INVALIDATKEY',
    30105 => 'UVE_UNABLETOLOADSUB',
    30106 => 'UVE_BADNUMARGS',
    30107 => 'UVE_SUBERROR',
    30108 => 'UVE_ITYPEFTC',
    30109 => 'UVE_ITYPEFAILEDTOLOAD',
    30110 => 'UVE_ITYPENOTCOMPILED',
    30111 => 'UVE_BADITYPE',
    30112 => 'UVE_INVALIDFILENAME',
    30113 => 'UVE_WEOFFAILED',
    30114 => 'UVE_EXECUTEISACTIVE',
    30115 => 'UVE_EXECUTENOTACTIVE',
    30124 => 'UVE_TX_ACTIVE',
    30125 => 'UVE_CANT_ACCESS_PF',
    30126 => 'UVE_FAIL_TO_CANCEL',
    30127 => 'UVE_INVALID_INFO_KEY',
    30128 => 'UVE_CREATE_FAILED',
    30129 => 'UVE_DUPHANDLE_FAILED',
    31000 => 'UVE_NVR',
    31001 => 'UVE_NPN',
    39101 => 'UVE_NODATA',
    39119 => 'UVE_AT_INPUT',
    39120 => 'UVE_SESSION_NOT_OPEN',
    39121 => 'UVE_UVEXPIRED',
    39122 => 'UVE_CSVERSION',
    39123 => 'UVE_COMMSVERSION',
    39124 => 'UVE_BADSIG',
    39125 => 'UVE_BADDIR',
    39127 => 'UVE_BAD_UVHOME',
    39128 => 'UVE_INVALIDPATH',
    39129 => 'UVE_INVALIDACCOUNT',
    39130 => 'UVE_BAD_UVACCOUNT_FILE',
    39131 => 'UVE_FTA_NEW_ACCOUNT',
    39134 => 'UVE_ULR',
    39135 => 'UVE_NO_NLS',
    39136 => 'UVE_MAP_NOT_FOUND',
    39137 => 'UVE_NO_LOCALE',
    39138 => 'UVE_LOCALE_NOT_FOUND',
    39139 => 'UVE_CATEGORY_NOT_FOUND',
    39201 => 'UVE_SR_SOCK_CON_FAIL',
    39210 => 'UVE_SR_SELECT_FAIL',
    39211 => 'UVE_SR_SELECT_TIMEOUT',
    40001 => 'UVE_INVALIDFIELD',
    40002 => 'UVE_SESSIONEXISTS',
    40003 => 'UVE_BADPARAM',
    40004 => 'UVE_BADOBJECT',
    40005 => 'UVE_NOMORE',
    40006 => 'UVE_NOTATINPUT',
    40007 => 'UVE_INVALID_DATAFIELD',
    40008 => 'UVE_BAD_DICTIONARY_ ENTRY',
    40009 => 'UVE_BAD_CONVERSION_ DATA',
    45000 => 'UVE_FILE_NOT_OPEN',
    45001 => 'UVE_OPENSESSION_ERR',
    45002 => 'UVE_NONNULL_RECORDID',
    80011 => 'UVE_BAD_LOGINNAME',
    80019 => 'UVE_BAD_PASSWORD',
    80144 => 'UVE_ACCOUNT_EXPIRED',
    80147 => 'UVE_RUN_REMOTE_FAILED',
    80148 => 'UVE_UPDATE_USER_FAILED',
    81001 => 'UVE_RPC_BAD_CONNECTION',
    81002 => 'UVE_RPC_NO_CONNECTION',
    81005 => 'UVE_RPC_WRONG_VERSION',
    81007 => 'UVE_RPC_NO_MORE_ CONNECTIONS',
    81009 => 'UVE_RPC_FAILED',
    81011 => 'UVE_RPC_UNKNOWN_HOST',
    81014 => 'UVE_RPC_CANT_FIND_ SERVICE',
    81015 => 'UVE_RPC_TIMEOUT',
    81016 => 'UVE_RPC_REFUSED',
    81017 => 'UVE_RPC_SOCKET_INIT_ FAILED',
    81018 => 'UVE_RPC_SERVICE_PAUSED',
    81019 => 'UVE_RPC_BAD_TRANSPORT',
    81020 => 'UVE_RPC_BAD_PIPE',
    81021 => 'UVE_RPC_PIPE_WRITE_ERROR',
    81022 => 'UVE_RPC_PIPE_READ_ERROR',
  }

  # Argument types
  TYPE_INTEGER = 0
  TYPE_FLOAT = 1
  TYPE_STRING = 2
  TYPE_BYTES = 3

  # Message types
  MESSAGE_LOGIN = 0x0F
  MESSAGE_OSCOMMAND = 0x06

  attr_reader :s

  # Build a unirpc packet. There are lots of arguments defined, pretty much all
  # of them optional.
  #
  # Header fields:.
  # * version_byte: The protocol version (this is always 0x6c in the protocol)
  # * other_version_byte: Another version byte (always 0x01 in the protocol)
  # * body_length_override: The length of the body (automatically calculated, normally)
  # * encryption_key: A field that defines how the "encryption" works - values
  #   below 2 XOR the packet by one value, and 2+ XOR by a different one (?)
  # * claim_compression: If true, tell the server that the message is compressed
  #   (we don't implement the compression)
  # * claim_encryption: If set, tell the server that the message is "encrypted"
  #   (XOR'd by a value) - doesn't actually do encryption
  # * do_encryption: If set, encrypt the message (you'll probably want to set
  #   claim_encryption as well)
  # * argcount_override: If set, specifies a custom number of "args"
  #   (automatically calculated, normally)
  #
  # Body fields:
  #
  # * body_override: If set, use it as the literal body and ignore the rest of these
  # * oldschool_data: The service supports two different types of serialized
  #   data; AFAICT, this field is just free-form string data that nothing really
  #   seems to support
  # * args: An array of arguments (the most common way to pass arguments to an
  #   rpc call).
  #
  # Args are an array of hashes with :type / :value
  # Valid types:
  # :integer - :value is the integer (32-bits)
  # :string / :bytes - value is the string or nil
  # :float - :value is just a 64-bit value
  #
  # String values also have an extra field, :null_terminate: true/false (default true)
  #
  # Set :skip_header to not attach a header
  # Set :debug to print out the raw packets
  def self.build_packet(
    version_byte: 0x6c,
    other_version_byte: 0x01,
    body_length_override: nil,
    encryption_key: 0x01,
    claim_compression: false,
    claim_encryption: false,
    do_encryption: false,
    argcount_override: nil,

    body_override: nil,
    oldschool_data: '',
    args: [],

    skip_header: false,
    debug: false
  )
    # Pack the args at the start of the body - this is kinda metadata-ish
    if body_override
      body = body_override
    else
      body = args.map do |a|
        case a[:type]
        when :integer
          # Ints ignore the first value, and the second is always 0
          [a[:extra] || 0x41424344, TYPE_INTEGER].pack('NN')
        when :string
          # Strings store the length in the first value, and the value in the body
          if a[:null_terminate].nil? || a[:null_terminate] == true
            [a[:value].length + 1, TYPE_STRING].pack('NN')
          else
            [a[:value].length, TYPE_STRING].pack('NN')
          end
        when :bytes
          # Strings store the length in the first value, and the value in the body
          [a[:value].length, TYPE_BYTES].pack('NN')
        when :float
          # Strings store the length in the first value, and the value in the body
          [a[:extra] || 0x45464748, TYPE_FLOAT].pack('NN')
        else
          $stderr.puts("Unknown type: #{ a[:type] }")
          exit 1
        end
      end.join('')

      # Follow it with the 'oldschool_data' arg
      body += oldschool_data

      # Follow that data section with the args - this is the value of the args
      body += args.map do |a|
        case a[:type]
        when :integer
          [a[:value]].pack('N')
        when :string
          str = a[:value]

          if a[:null_terminate].nil? || a[:null_terminate] == true
            str += "\0"
          end

          # Align to multiple of 4, always adding at least one
          str += "y"
          while (str.length % 4) != 0
            str += "Y"
          end

          str
        when :bytes
          str = a[:value]

          # Alignment
          while (str.length % 4) != 0
            str += "X"
          end
          str
        when :float
          [a[:value]].pack('Q')
        else
          $stderr.puts("Unknown type: #{ a[:type] } (you probably forgot to implement the second half of encoding)")
          exit 1
        end
      end.join('')
    end

    # "Encrypt" if we're supposed to
    if do_encryption
      encryption_key = encryption_key < 2 ? 1 : 2
      body = body.bytes.map do |b|
        (b ^= encryption_key).chr
      end.join('')
    end

    # Figure out the argcount
    if argcount_override
      argcount = argcount_override
    else
      argcount = args.length

      # If we pass plaintext data, it actually counts as an extra arg
      if oldschool_data != ''
        argcount += 1
      end
    end

    if skip_header
      if debug
        print body
      end
      return body
    end

    header = [
      version_byte, # Has to be 0x6c
      other_version_byte, # Can be 0x01 or 0x02
      'Z'.ord, # Padding
      'Z'.ord, # Padding

      body_length_override || body.length, # Length of data (XXX: 0x7FFFFFFF => heap overflow)

      0x41424344, # Padding

      encryption_key,            # 0-1 and 2+ have different effects (possibly just on the encryption)
      claim_compression ? 1 : 0, # Compression (boolean, I think - zero/non-zero)
      claim_encryption ? 1 : 0,  # Encryption (0 = not encrypted, 1 = encrypted)
      'Y'.ord,                   # Padding

      0x00000000,                # Unknown, but has to be 0

      argcount,                  # Argcount, which we compute earlier
      oldschool_data.length      # Data length
    ].pack('CCCCNNCCCCNnn')

    packet = header + body
    if debug
      print packet
    end

    return packet
  end

  def self.recv_packet(s)
    # Receive the header
    header = s.recv(0x18)

    # Make sure we received all of it
    if header.nil?
      $stderr.puts("Disconnected!")
      return nil
    elsif header.length < 0x18
      $stderr.puts("Received #{ header.length } bytes, require at least 24 for the header")
      return nil
    end

    # Parse out the fields
    (
      version_byte,
      other_version_byte,
      reserved1,
      reserved2,

      body_length,

      reserved3,

      encryption_key,
      claim_compression,
      claim_encryption,
      reserved4,

      reserved5,

      argcount,
      data_length,
    ) = header.unpack('CCCCNNCCCCNnna*')

    # Note: we don't attempt to decrypt / decompress here, because we've never
    # seen a server actually enable encryption
    results = {
      header: header,
      version_byte: version_byte,
      other_version_byte: other_version_byte,
      body_length: body_length,
      encryption_key: encryption_key,
      claim_compression: claim_compression,
      claim_encryption: claim_encryption,
      argcount: argcount,
      data_length: data_length,
    }

    # Receive the body
    body = s.recv(body_length)

    # Parse the argument metadata, data, and argument data
    args, data, extra_data = body.unpack("a#{argcount * 8}a#{data_length}a*")

    # Parse the argument metadata + data
    results[:args] = []
    1.upto(argcount) do
      arg, args = args.unpack('a8a*')
      (value, type) = arg.unpack('NN')

      case type
      when 0 # 32-bit integer
        (arg_data, extra_data) = extra_data.unpack('Na*')

        results[:args] << {
          type: :integer,
          value: arg_data,
          extra: value,
        }
      when 2 # Null-able string
        if value == 0
          string_value = nil
        else
          # TODO: We probably need to deal with alignment padding
          (string, extra_data) = extra_data.unpack("a#{value}a*")
          string_value = string
        end

        results[:args] << {
          type: :string,
          value: string_value,
          extra: value,
        }
      when 3 # They call this "RPC String"
        (string, extra_data) = extra_data.unpack("a#{value}a*")
        string_value = string

        results[:args] << {
          type: :string,
          value: string_value,
        }
      else
        throw "Don't know how to deal with arg type #{ type } yet!"
      end
    end

    return results
  end

  def initialize(host, port)
    # Connect
    @s = TCPSocket.new(host, port)
  end

  def send(...)
    packet = LibNeptune::build_packet(...)
    @s.write(packet)
  end

  def recv()
    return LibNeptune::recv_packet(@s)
  end

  def send_recv(**args)
    $stderr.puts "Request:"
    $stderr.puts(args.pretty_inspect)
    $stderr.puts
    packet = LibNeptune::build_packet(**args)
    @s.write(packet)

    response = LibNeptune::recv_packet(@s)
    $stderr.puts "Response:"
    $stderr.puts response.pretty_inspect
    $stderr.puts

    return response
  end

  def close()
    @s.close()
  end
end
