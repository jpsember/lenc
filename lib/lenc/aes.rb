require_relative 'tools'

require 'openssl'


module RepoInternal
  
# --------------------------------------------------------------

  AES_BLOCK_SIZE = 16
  PAD_BYTE = 254
  PAD_CHAR = PAD_BYTE.chr
  
  CHUNK_HEADER_SIZE = 8
  CHUNK_VERIFY_SIZE = CHUNK_HEADER_SIZE - 1
  CHUNK_VERIFY_STR = 0.chr * CHUNK_VERIFY_SIZE
  
  # Size of input chunks during decryption (they include space for a header);
  # must be a multiple of AES_BLOCK_SIZE
  CHUNK_SIZE_DECR = 1 << 16
  
  # Size of input chunks during encryption
  CHUNK_SIZE_ENCR = CHUNK_SIZE_DECR - CHUNK_HEADER_SIZE
  
  # The size of nonce the underlying API expects
  NONCE_SIZE_LARGE = 16
      
  # The size of nonce we'll be using (we'll pad it out with zeros 
  # when a full size one is required)
  NONCE_SIZE_SMALL = 8
  
 
    
=begin
    Wrapper for OpenSSL AES cipher.
    
  
    Usage for encryption:
    ----------------------------------------------------
    original = "..."          # bytes to encrypt (string)
    
    key = "xxxx..."           # encryption key (string of size 8..56)
    
    en = MyAES.new(true, key) # construct an encryptor    
    
    en.finish(original)       # add data to encrypt          
    
    encrypted = en.flush()    # get encrypted bytes (string)
    ----------------------------------------------------
    
  
      
    Usage for decryption:
    ----------------------------------------------------
    encrypted = "..."         # bytes to decrypt 
    
    key = "xxxx...."    
    
    de = MyAES.new(false, key)  # construct a decryptor
    
    de.finish(original)       # add data to decrypt
    
    decrypted = de.flush()    # get decrypted bytes
    
    ----------------------------------------------------
      
  
    Use of nonces:
    --------------
    The above encryption example generates a new (hopefully unique) 'nonce' 
    which is an added security feature.  It uses the system clock to do this.
    This means the same file will produce different encrypted byte streams on 
    repeated encryption attempts, which may be undesirable.  A fixed nonce
    (for a particular input file) can be specified as an additional input:
  
    nonce = "nnnn.."         # only the first 8 bytes are used
    en = MyAES.new(true, key, nonce)
    
    The nonce, whether explicitly given or randomly generated, is added to the
    encrypted stream; hence it need not be specified when decrypting.
    
    Stream mode:
    ------------
    When processing large files, you may want to do them a chunk at a time.
    Here's an example of encrypting using stream mode (decrypting is similar):
    
    
    en = MyAES.new(true, key)    
    
    s = {size of input file}
    n = 0
    while n < s  
      c = [5000, s - n].min
      en.add( {bytes n..n+c-1 from the input file} )
      r = en.flush()
      {append bytes r to output file}
    end
  
    en.finish()
    r = en.flush()
    {append bytes r to output file}
    
    ----------------------------------------------------
     
    Format of encrypted data:
    
    [8] nonce (only the first 8 bytes of the nonce are actually used)
    
    Followed by one or more encrypted chunks of length [k], where k is 65536, unless it's the last
    chunk in the file, in which case it must be a multiple of 16.
  
    The first bytes of each decrypted chunk is a header:
      [7]  zeros
      [1]  number of padding bytes present at end of block
       
       
    For example, suppose a file of 71980 'source' bytes has been encrypted.  The encrypted file will contain:
      [8] nonce
      [65536] first chunk, consisting of
         [7] zeros
         [1] zero, since this chunk needed no padding
         [65528] 65528 encrypted source bytes
      [6464]  second chunk, consisting of
         [7] zeros
         [1] 4, indicating 4 padding bytes
         [6456] 6452 encrypted source bytes plus 4 padding bytes 
         
      Observe that 65528 + 6452 = 71980.
    
    The purpose of the [7] zeros in the (decrypted) chunk header are to indicate
    whether decryption was successful (e.g., if the password was correct).  The assumption
    is that an incorrect password will generate 7 zeros in these locations with extremely low probability.
       
    The byte used as a padding byte is 254.
    
    If a file has length zero, then when encrypted, it will have the following structure:
      [8] nonce
      [16] chunk:
        [7] zeros
        [1] 8, indicating 8 padding bytes
        [8] 0 encrypted source bytes plus 8 padding bytes
      
=end
  class MyAES 
    
    private
    
    # decryptState values
    DS_WAITNONCE = 0 # waiting for nonce to appear in input
    DS_WAITCHUNK = 1 # waiting for encrypted chunk to appear 
    
    # A class variable that increments with each encryptor object constructed,
    # to help generate unique nonces (in conjunction with system clock)
    @@nonceHelper = 0
      
    # Construct a MyAES object to encrypt/decrypt a sequence of bytes.
    # @param encrypting true for encryption, false for decryption
    # @param key   a bytearray of 4..56 bytes
    # @param nonce  a string of up to 16 characters; if nil, one is 
    #   generated from the system clock
    def initialize(encrypting, key, nonce=nil)
      
      @encrypting = encrypting
      @inputBuffer = ''
      @outputBuffer = ''
      @finished = false
      
      if nonce && !encrypting
        raise ArgumentError, \
         "nonce should not be supplied during decryption"
      end 
      
      if @encrypting
        @nonceWritten = false
      else 
        @decryptState = DS_WAITNONCE
      end
      
      key = bytes_to_str(key)
        
      if key.size < 4 || key.size > 56
          raise ArgumentError, 'Key length not 4..56 bytes' 
      end
        
      # expand the key to be at least 32 bytes
      k = (32.0 / key.size).ceil.to_i
      key = key * k
      
      @key = key[0...32]
      @chunkCount = 0
      
      # If we are encrypting, set nonce; otherwise, we must wait for some data to be available
      if @encrypting 
        setNonce(nonce) 
      else
        @chunkExpected = true
      end
    end
    
    # Set nonce
    # @param nonce a string; if nil, uses system clock and an internal
    #   counter to generate (hopefully) a unique value
    def setNonce(nonce=nil)
      if !nonce
          # use date-time if no counter provided
          ni = int_to_bytes(Time.now.usec)
          ni.concat(int_to_bytes(@@nonceHelper))
          @@nonceHelper += 1
          nonce = bytes_to_str(ni)
      end
      
      raise ArgumentError if !(nonce.is_a? String )
      simple_str(nonce)
      
      
      nonce = str_sized(nonce,NONCE_SIZE_SMALL)
      
      @nonce = nonce
    end  
  
    def incrNonce()
      c = @nonce
      dig = NONCE_SIZE_SMALL - 1
      while true
        raise ArgumentError, "Nonce overflow" if dig < 0
        
        q = c[dig].ord
        if q != 0xff 
          c[dig] = (q+1).chr
          break
        end
        
        c[dig] = 0.chr
        dig -= 1
      end
    end
    

    # Convert nonce from our version to one the OpenSSL expects.
    # This may involve padding or truncating it as necessary to a
    # fixed length.
    def cvtNonce()
      str_sized(@nonce,NONCE_SIZE_LARGE)
    end
    
    def buildAES()
      aes = OpenSSL::Cipher.new("AES-256-CBC")
      aes.padding = 0  # Not sure this is required, as we are doing padding ourselves;
                       # we should only be asking it to process blocks that need no padding
      aes
    end
    
    def processChunk()
  
      if @encrypting 
          
        csize = [CHUNK_SIZE_ENCR, @inputBuffer.size].min
        
        padBytes = (-(csize + CHUNK_HEADER_SIZE)) & (AES_BLOCK_SIZE - 1)
        
        csize += padBytes
        
        if padBytes 
          @inputBuffer << PAD_CHAR * padBytes
        end
        
        aes = buildAES()
        aes.encrypt
        aes.key = @key
        nonceStr = cvtNonce
        aes.iv = nonceStr
        
        if not @nonceWritten 
          @nonceWritten = true
          @outputBuffer  << nonceStr[0...NONCE_SIZE_SMALL]
        end
                  
        cdata = "\0" * CHUNK_VERIFY_SIZE
        cdata << padBytes.chr
        cdata << @inputBuffer.slice!(0,csize)  
          
        @outputBuffer << aes.update(cdata)
        @outputBuffer << aes.final
        
      else  # Decrypting
        
        csize = [CHUNK_SIZE_DECR,@inputBuffer.size].min
        
        # verify that the chunk size is a nonzero multiple of AES_BLOCK_SIZE bytes
        if not csize or 0 != (csize & (AES_BLOCK_SIZE - 1)) 
          raise LEnc::DecryptionError, "chunk size not a multiple of block size" 
        end
        
        aes = buildAES()
        aes.decrypt
        aes.key = @key
        aes.iv = cvtNonce()
        
        cdata = @inputBuffer[0...csize]
        newData = aes.update(cdata) 
        newData << aes.final

        if !newData.start_with? CHUNK_VERIFY_STR
          raise LEnc::DecryptionError, "header doesn't verify"
        end
          
        nPadBytes = newData[CHUNK_VERIFY_SIZE].ord  
        actualEnd = csize - nPadBytes
        if nPadBytes > 16 or actualEnd < CHUNK_HEADER_SIZE 
          raise LEnc::DecryptionError, "nPadBytes/actualEnd mismatch"
        end  
        
        

        # Verify that the padding bytes have correct values
        (actualEnd...csize).each do |i|
          if newData[i] != PAD_CHAR
            raise LEnc::DecryptionError,"padding char bad value"
          end
        end
          
        newData = newData[CHUNK_HEADER_SIZE ... actualEnd]
          
        @decryptState = DS_WAITCHUNK
          
        @inputBuffer.slice!(0,csize)
        @outputBuffer  << newData
        
      end
      
      incrNonce()
      @chunkCount += 1
    end
    
    public
     
    # Process additional input bytes, encrypting (or decrypting) its contents
    # @param data string containing input bytes
    def add(data)
       
      raise IllegalStateException if @finished 
      
      simple_str(data)
      
      @inputBuffer << data #.concat(data)
    
      while true 
    
        if not @encrypting 
          
          # Extract nonce if we're waiting for it and it is now available
          if @decryptState == DS_WAITNONCE 
            break if @inputBuffer.size <  NONCE_SIZE_SMALL 
            setNonce(@inputBuffer.slice!(0...NONCE_SIZE_SMALL))  
            @decryptState = DS_WAITCHUNK
            next
          end
          
          # If we don't have a full chunk, exit
          # (the last chunk may be smaller; we'll test for this when finishing up)
          break if @inputBuffer.size < CHUNK_SIZE_DECR
          
        else 
          break if @inputBuffer.size < CHUNK_SIZE_ENCR
        end  
        
        # Process chunk and repeat
        processChunk()
      end
    end

    # Stop the encryption/decryption process.  
    # Processes any bytes that may have been buffered (since encryption occurs in 
    # 16 byte blocks at a time).
    # 
    # @param data   optional final input string to process before finishing
    # 
    def finish(data = nil) 
      
      add(data) if data 
        
      raise IllegalStateException if @finished  
      
      @finished = true
      
      inpLen = @inputBuffer.size
      
      if @encrypting 
        # If input buffer is not empty, or we haven't written a first chunk (which contains the nonce),
        # encrypt a chunk
        if inpLen or (not @nonceWritten) 
          processChunk()
        end
      else
        
        # We must be at WAITCHUNK with an input buffer that is a multiple of _AES_BLOCK_SIZE bytes in length
        if @decryptState != DS_WAITCHUNK or 0 != (inpLen & (AES_BLOCK_SIZE-1)) 
          raise LEnc::DecryptionError, "decrypt state problem"
        end
        
        # We expect a chunk if there's more input, or if we've never processed a chunk.
        if inpLen != 0 or @chunkCount == 0
          processChunk()
        end
      end
    end
        
      
    # Return any output bytes that have been generated since the last call to flush()
    # @return string containing bytes
    def flush()
      ret = @outputBuffer 
      @outputBuffer = ''
      return ret
    end

    # Strip the header from an encrypted string
    def strip_encryption_header( encr_str)
      return encr_str[CHUNK_HEADER_SIZE..-1]
    end
        
    # Determines if a string is the start of an encrypted sequence
    # 
    # @param key  password to use (string) 
    # @param test_str the string to test
    #  
    # Returns true iff the start of the string seems to decrypt correctly
    # for the given password
    def self.is_string_encrypted(key, test_str) 
      db = warndb 0
      
      !db || hex_dump(test_str, "areBytesEncrypted?")
      
      simple_str(test_str)
      
      lnth = test_str.size
      lnth -= NONCE_SIZE_SMALL
      if lnth < AES_BLOCK_SIZE 
        !db || pr("  insufficient # bytes\n")
        return false
      end
      
      begin
          de = MyAES.new(false, key)    
          de.finish(test_str[0...AES_BLOCK_SIZE + NONCE_SIZE_SMALL])
          decr = de.flush()
          !db || hex_dump(decr,"decrypted successfully")
      rescue LEnc::DecryptionError
        !db || pr(" (caught DecryptionError)\n")
        return false
      end
        
      true
    end
      
    # Determines if a file is an encrypted file
    # @param key    password to use (string, or array of bytes) 
    # @param path    path to file
    # @return true iff the start of the file seems to decrypt correctly
    # for the given password, and the file is of the expected length.
    def self.is_file_encrypted(key, path) 
      
    #    key = str_to_bytes(key)
      
      if not File.file?(path) 
        return false
      end
      
      lnth = File.size(path)
      minSize = NONCE_SIZE_SMALL + AES_BLOCK_SIZE
      if lnth < minSize or ((lnth - minSize) % _AES_BLOCK_SIZE) != 0
        return false
      end
      
      f = File.open(path,"rb")
      return is_string_encrypted(key, f.read(minSize))
    end
  
  
  end # end of class MyAES

end # module RepoInternal


if main? __FILE__
  
  s = ''
  16.times {|x| s << (65+x).chr}
    

  nonce  = "abc" * 20
  nonce  = nonce[0...16]
  key = "onefishtwofishredfishbluefish" * 3
  key = key[0...32]
  
  hex_dump(key,"key")
  hex_dump(nonce,"nonce")
  
  aes = OpenSSL::Cipher.new("AES-256-CBC")
      
  aes.padding = 0
  aes.encrypt
  aes.key = key
        
  aes.iv = nonce
        
  enc = aes.update(s)
  enc << aes.final
        
  hex_dump(s,"calling aes.encrypt with")
  hex_dump(enc,"aes.encrypt returned")

  s = enc
  
  require 'base64'
  s = Base64.urlsafe_encode64(s)
  hex_dump(s,"base64")

end