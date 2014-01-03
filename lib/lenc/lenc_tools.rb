#!/usr/bin/env ruby

module LencTools

  module_function

# Construct a string from an array of bytes
# @param byte_array array of bytes, or string (in which case it
#   returns it unchanged)
#
def bytes_to_str(byte_array)
  return byte_array if byte_array.is_a? String

  byte_array.pack('C*')
end

# Construct an array of bytes from a string
# @param str string, or array of bytes (in which case it
#   returns it unchanged)
#
def str_to_bytes(str)
  return str if str.is_a? Array
  str.bytes
end

# Get directory entries, excluding '.' and '..'
#
def dir_entries(path)
  ents = Dir.entries(path)
  ents.reject!{|entry| entry == '.' || entry == '..'}
end

def int_to_bytes(x)
  [(x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff]
end

def short_to_bytes(x)
  [(x >> 8) & 0xff, x & 0xff]
end

# Decode a short from an array of bytes (big-endian).
# @param ba array of bytes
# @param offset offset of first (most significant) byte
#
def short_from_bytes(ba, offset=0)
  (ba[offset] << 8) | ba[offset + 1]
end

# Decode an int from an array of bytes (big-endian).
# @param ba array of bytes
# @param offset offset of first (most significant) byte
#
def int_from_bytes(ba, offset=0)
  (((((ba[offset] << 8) | ba[offset + 1]) << 8) | \
      ba[offset + 2]) << 8) | ba[offset + 3]
end

# Transform string to 8-bit ASCII (i.e., just treat each byte as-is)
#
def to_ascii8(str)
  str.force_encoding("ASCII-8BIT")
end

# Verify that a string is encoded as ASCII-8BIT
def simple_str(s)
  if s.encoding.name != 'ASCII-8BIT' && s.encoding.name != 'UTF-8'
    die("string [%s]\n encoding is %s,\n expected ASCII-8BIT\n",s,s.encoding.name)
  end
end

# Determine if running on the Windows operating system.
# Note: there is some debate about the best way to do this.
#
def windows?
  if !defined? $__windows__
    $__windows__ = (RUBY_PLATFORM =~ /mswin/)
  end
  $__windows__
end

end

