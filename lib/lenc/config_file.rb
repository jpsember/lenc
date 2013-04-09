require 'json'
require_relative 'tools'

module LEnc

  # Manages a configuration file, which
  # is a set of key/value pairs that can be saved to the file system.
  #
  class ConfigFile 
  
    attr_reader :path
    
    # @param filename where configuration file is to be found (or written to,
    #    if it doesn't yet exist)
    # @param parentDir directory containing file; if nil, uses user's home directory
    #
    def initialize(filename, parentDir=nil) 
      
      parentDir ||= Dir.home
        
      @path = File.join(parentDir, filename)
      
      @content = {}
      @origContentStr = "!!!"
      if exists()
        contents = read_text_file(@path).strip
        
        @content = JSON.parse(contents)
        @origContentStr = JSON.dump(@content)
      end
    end
  
    # Determine if configuration file exists on disk
    def exists()
      File.exists?(@path)
    end
  
    # Get the directory containing the configuration file
    def get_directory()
      File.dirname(@path)
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
        write_text_file(@path,@origContentStr + "\n")
      end
    end
     
    # Get value for a key
    # @param defVal value to return if key doesn't exist
    def val(key, defVal = nil)
      @content[key] || defVal
    end
      
    def to_s
      s = 'ConfigFile ' 
      s << path()
      s << dh(@content)
#      " [\n"
#      @content.each_pair do |k,v|
#        s << d(k) << ' ==> ' << d(v) << "\n"
#      end
#      s << "]\n"
      s 
    end
    
    def inspect
      to_s
    end  
    
  end # Class
end # Module


if main? __FILE__

  include LEnc
  
  f = ConfigFile.new("__testrbconfig__.txt")
  
  pr("constructed:\n%s\n",d(f))
  
  srand
  "alpha bravo echo geronimo".split.each do |s|
    n = s.size
    if rand() > 0.8
      n = rand(12)
    end
    f.set(s,n)
  end
  
  f.write
  
end
