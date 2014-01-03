require 'json'

module LEnc

  # Manages a configuration file, which
  # is a set of key/value pairs that can be saved to the file system.
  #
  class ConfigFile

    attr_reader :path

    def initialize(path)
      @path = path
      @content = {}
      @origContentStr = nil
      if File.exists?(@path)
        contents = FileUtils.read_text_file(@path).strip
        @content = JSON.parse(contents)
        @origContentStr = JSON.dump(@content)
      end
    end

    # Store a key => value pair (any existing value for this key is overwritten)
    def set(key,val)
      @content[key] = val
    end

    # Remove key (and value), if it exists
    def remove(key)
      @content.remove(key)
    end

    # Write configuration file, if it has changed
    def write
      newStr = JSON.dump(@content)
      if newStr != @origContentStr
        @origContentStr = newStr
        FileUtils.write_text_file(@path,@origContentStr + "\n")
      end
    end

    # Get value for a key
    # @param defVal value to return if key doesn't exist
    def val(key, defVal = nil)
      @content[key] || defVal
    end

  end # Class
end # Module
