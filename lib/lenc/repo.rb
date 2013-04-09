require 'base64'
require 'pathname'
require 'fileutils'
require 'tempfile'

require_relative 'tools'
req('aes config_file')

module RepoInternal
  class IgnoreEntry 
    attr_accessor :dirOnly, :negated, :pathMode, :rexp, :dbPattern
    
    # Representation of a .lencignore entry
    def initialize
      @dirOnly, @negated, @pathMode, @rexp, @dbPattern = nil
    end  
    
    def inspect
      to_s
    end
    def to_s
      s = "Ign<"
      s << df(@dirOnly,"dirOnly") << "expr: " << @rexp.to_s << ">"
      s
    end
  end
end


module LEnc

  class DecryptionError < Exception 
  end

  class RepoNotFoundException < Exception
  end
  
  class EncryptionVerificationException < Exception
  end  

  class VersionException < Exception
  end 

  class RecoveryException < Exception
  end  
  
  class UpdateException < Exception
  end  
  
  # Represents an encrypted repository
  #
  class Repo
    
    include RepoInternal
    
    # The filename that represents a repository; it is
    # stored in the repository's root directory. """
    if windows?
      LENC_REPO_FILENAME = "__lenc_repo__.txt"  
    else
      LENC_REPO_FILENAME = ".lenc"
    end
    
    ENCRFILENAMEPREFIX = "_#"
  
   
    private
    
    RESPECIALPAT = Regexp.new('^[\.\^\$\*\+\?\{\}\\\|\!\:\)\(\[\]]$')
    
    if windows?
      IGNOREFILENAME = "__lencignore__.txt"
    else
      IGNOREFILENAME = ".lencignore"
    end
    
    
    DEFAULTIGNORE = \
      "#{LENC_REPO_FILENAME}\n " \
       ".DS_Store\n" + \
      ".recoverdefaults\n"

    STATE_CLOSED = 0
    STATE_OPEN = 1
    
    public
     
    # Construct a repository object.  It is created in a 'closed' state, in that it
    # is not associated with a particular repository in the file system. 
    #
    # @param options hash table of optional parameters; e.g.
    #        r = LEnc::Repo(:verbosity => 2, strict => True)
    #
    #   :dryrun if true, no files on the filesystem will be affected by this
    #       object throughout its lifetime.  Useful for showing the user what
    #       would happen if dryrun were false.
    #   :verbosity controls the amount of feedback during this object's lifetime.
    #        default 0; if < 0, silent; if > 0, talkative
    #
    def initialize(options = {})
     
      reset_state()
      
      @dryrun = options.delete :dryrun
      @verbosity = (options.delete :verbosity) || 0
      
      # During recovery, we will use the first file we encounter to 
      # verify if the supplied password is correct, and abort if not.
      @recovery_pwd_verified = false
      
      if options.size > 0
        raise ArgumentError, "Unrecognized options: " + d2(options)
      end
    end
    

    # Create a new encryption repository, and open it. 
    # 
    # @param repo_dir  directory of new repository (nil for current directory)
    # @param key      encryption key, a string from 8 to 56 characters in length
    # @param enc_dir   directory to store encrypted files; must not yet exist, and must
    #                 not represent a directory lying within the repo_dir tree
    # @param original_names   if true, the filenames are not encrypted, only the file contents
    # @param store_key  if true, the key is written to the repository configuration file; otherwise,
    #                   user must supply the key every time the repository is updated
    # @raise ArgumentError if appropriate
    #
    def create(repo_dir, key, enc_dir, original_names=false, store_key=true) 
      raise IllegalStateException if @state != STATE_CLOSED 
      
      db = warndb 0
      !db || pr("Repo.create, %s\n",da( [repo_dir,key,enc_dir,original_names]))
      repo_dir ||= Dir.pwd

      if  !File.directory?(repo_dir)
        raise ArgumentError, "Not a directory: #{repo_dir}"
      end
      
      # Verify that there is no repository. 
      # Construct a ConfigFile object to determine if it already exists
      @confFile = ConfigFile.new(LENC_REPO_FILENAME, repo_dir)
      
      if @confFile.exists()
        raise ArgumentError, 'Encryption repository already exists: ' \
         + @confFile.path
      end
      
      @confFile.set('version', @version)
      
      @orignames = original_names
      
      edir = File.absolute_path(enc_dir)
      @confFile.set('orignames', @orignames)
      
      if @verbosity >= 0 
          pr("Creating encryption repository %s\n", @confFile.path)
      end
      
      pp = verifyDirsDistinct([repo_dir, edir])
      
      if pp
        raise ArgumentError, "Directory " + pp[0] + \
         " is a subdirectory of " + pp[1] 
      end
        
      if (key.size < 8 || key.size > 56) 
        raise ArgumentError, "Password length " + key.size.to_s \
          + " is illegal" 
      end
        
      if store_key
        @confFile.set('key', key)
      end
      
      # Construct a string that verifies the password is correct
      en = MyAES.new(true, key  )
      en.finish("!!!")            
      verifier_string = en.flush

      # Store key verifier as an array of bytes, to avoid nonprintable problems
      vs2 = Base64.urlsafe_encode64(verifier_string)
      @confFile.set('key_verifier', vs2)
      
      
      # Create encryption directory
      if File.exists?(edir)
        raise ArgumentError, \
        "Encryption directory or file already exists: '#{edir}'"
      end
      
      @confFile.set('enc_dir', edir)
      
      if not @dryrun 
        Dir.mkdir(edir)
        @confFile.write()
      end
      
    end
  
      
    # Open the repository, by associating it with one in the file system.
    # 
    # @param startDirectory  directory lying within repository tree; if nil, uses
    #       current directory
    # @param password repository password; if a password was stored with the repository
    #       when it was created, this parameter is ignored; if this parameter is null, and
    #       no password was stored with the repository, the user will be prompted for one
    # @raise  IllegalStateException if repository is already open 
    # @raise  ArgumentError if directory doesn't exist, or does not lie in a repository 
    #
    def open(startDirectory=nil, password = nil) 
      db = warndb 0
      !db || pr("Repo.open startDir=%s\n",d(startDirectory))
        
      raise IllegalStateException if @state != STATE_CLOSED 
        
      startDirectory ||= Dir.pwd
      
      if not File.directory?(startDirectory)
          raise ArgumentError,"Not a directory: '" + startDirectory + "'"
      end
    
      cfile = Repo.findRepository(startDirectory)
      !db || pr(" find repo (%s) => %s\n",d(startDirectory),d(cfile))
        
      if !cfile 
        raise RepoNotFoundException, "Can't find repository"
      end
  
      @confFile = cfile
      @startDir = startDirectory
      @repoBaseDir = cfile.get_directory 
      
      cfVersion = @confFile.val('version', 0)
      if cfVersion > @version 
        raise(VersionError,"Repository was built with a more recent version of the program.")
      end
      
      if cfVersion.floor < @version.floor
        raise(VersionError,"Repository was built with an older version; rebuild it")
      end
      
      # Read values from configuration to instance vars
      @encrDir = @confFile.val('enc_dir')
      pwd = @confFile.val('key') || password
      if !pwd
        printf("Password: ")
        pwd = gets
        if pwd
          pwd.strip!
          pwd = nil if pwd.size == 0
        end
        if !pwd
          raise DecryptionError, "No password given"
        end
      end
      
      @orignames = @confFile.val('orignames')
      @encrKey = pwd
      
      prepareKeys()
      
      key_verifier = @confFile.val('key_verifier')
      key_verifier = Base64.urlsafe_decode64(key_verifier)
            
      verify_encrypt_pwd(pwd, key_verifier)
      
      @state = STATE_OPEN
    end
  
    # Close the repository, if it is open
    def close 
      return if @state == STATE_CLOSED
      
      raise IllegalStateException if @state != STATE_OPEN
      
      reset_state()
    end
   
    # Update the repository.  Finds files that need to be re-encrypted and does so.
    # Repository must be open.
    # 
    # @param verifyEncryption for debug purposes; if true, each file that is encrypted is tested to confirm that
    #   it decrypts correctly.
    #     
    # @raise IllegalStateException if repository isn't open.
    # 
    def perform_update(verifyEncryption=false)
      raise IllegalStateException if @state != STATE_OPEN
      
      setInputOutputDirs(@startDir,@encrDir)
      
      @verifyEncryption = verifyEncryption
      
      puts("Encrypting...") if @verbosity >= 1

      begin
        encryptDir(@repoBaseDir, @encrDir)
        puts("...done.") if @verbosity >= 1
      end
    end
         
  
    # Recover files from a repository's encryption folder.
    # 
    # @param key   encryption key
    # @param eDir  encryption directory
    # @param rDir directory to write decrypted files to; creates it if necessary.
    #              Must not lie within eDir tree.
    # 
    # @raise ArgumentError if problem with the directory arguments;
    # @raise DecryptionError if incorrect password provided, and strict mode in effect
    #
    def perform_recovery(key, eDir, rDir) 
      raise IllegalStateException  if @state != STATE_CLOSED
      
      ret = nil
      
      @encrKey = key
      
      rd = File.absolute_path(rDir)
      prepareKeys()
      
      if not File.directory?(eDir)
        raise ArgumentError, "Not a directory: '" + eDir + "'" 
      end
  
      # There must not exist a repository in the recovery directory
      cf = Repo.findRepository(rd)
      
      if cf 
        raise ArgumentError, "Recovery directory lies within repository: " + cf.getPath()
      end
      
      puts("Recovering...") if @verbosity >= 1
      
      setInputOutputDirs(eDir,rd)
    
      begin
        recover(eDir, rd)
        print("...done.") if @verbosity >= 1 
      end
        
      ret
    end
    
    private
    
    def setInputOutputDirs(inp,outp)
      @inputDir = File.absolute_path(inp)
      @outputDir = File.absolute_path(outp)
    end

    # Determine if no paths in a list lie in a subdirectory of another 
    def verifyDirsDistinct(dirList) 
      dirList.each_with_index do |di,i|
        dirList.each_with_index do |dj,j|
          next if i == j
          if di.start_with? dj
            return [di,dj]
          end
        end
      end
      nil
    end
    
     
    # Starting in a particular directory, attempt to find the nearest 
    # parent repository.
    #     
    # returns ConfigFile, or nil
    #
    def self.findRepository(startDir) 
      bp = File.absolute_path(startDir)
      while true
        
        # Construct a ConfigFile object to determine if it already exists
        cfile = ConfigFile.new(LENC_REPO_FILENAME, bp)
        return cfile if cfile.exists
        
        prev_bp = bp
        bp = File.dirname(bp)
        return nil if prev_bp == bp
      end
    end
    
      
    # Parse an ignore list into a list of IgnoreEntries.
    #       
    # @param text a script, each line of which describes a pattern
    #
    def self.parseIgnoreList(text, ignPath="(unknown)") 
      
      db = false
      
      ret = []
      
      text.split("\n").each do |ln|
        begin
          
          ln.strip! 
          !db || pr("...parsing line [#{ln}]...\n")
          
          # Determine if it's a comment
          if ln.start_with?("\\#") 
            ln = ln[1..-1]
          else 
            if ln.start_with?("#") 
              ln = ""
            end
          end
          
          ient = IgnoreEntry.new
          
          # Determine if it's a negated pattern
          
          if ln.start_with?("\\!") 
            ln = ln[1..-1]
          else 
            if ln.start_with?("!")
              ln = ln[1..-1]
              ient.negated = true
            end
          end
          
          # Determine if it should represent directories only
          
          if ln.end_with?('/')
            ient.dirOnly = true
            ln = ln[0..-2]
          end
          
          next if not ln  # comment or blank line, skip
          
          # Now we see if there are any path separators in the expression.
          # If so, we set pathMode.
          
        
          ient.pathMode = ln.include? '/'
          
          # Convert expression to regular expression.
          #
          #   *     => .*
          #   ?     => . 
          #   [...] => [...]
          #   [!..] => [^...]
          
          pat = ''
          
          inBrace = false
          i = -1
          while true
            i += 1
            break if i >= ln.size
            
            ch = ln[i]
            ch2 = (i+1 < ln.size) ? ln[i+1] : ''
                
            if inBrace 
              if ch == ']' 
                pat << ']'
                inBrace = false
                next
              end
            else 
              if ch == '[' 
                inBrace = true
                pat << '['
                if ch2 == '!' 
                  i += 1
                  pat << '^'
                end
                next
              end
              
              if ch == '*'
                if ient.pathMode 
                  pat << '[^/]*'
                else
                  pat << '.*'
                end
                next
              end
              
              if ch == '?'
                if ient.pathMode 
                  pat << '[^/]?'
                else
                  pat << '.?'
                end
                next
              end
            end
            
            if '[]'.include? ch
               raise Exception, "Problem with ignore pattern" 
            end
            
            if RESPECIALPAT.match(ch)
              pat << '\\' << ch
              next
            end
            
            pat << ch
          
          end
          
          ient.rexp = Regexp.new('^' + pat + '$')
          ient.dbPattern = pat
          
          ret.push(ient)
        end
      end
      return ret
    end
      
    def reset_state 
      @state = STATE_CLOSED
      @encrKey = nil
      @encrKey2 = nil
      @confFile = nil
      @repoBaseDir = nil
      @encrDir = nil
      @version = 2.0
      @orignames = false
      initIgnoreList()
    end
       
    # Construct the initial ignore list.  
    #       
    # We maintain a stack of these lists, and subsequent operations can push and pop
    # additional ignore lists onto this stack as it recursively descends into subdirectories.
    #       
    def initIgnoreList 
      @ignoreStack = []
      pushIgnoreList('', Repo.parseIgnoreList(DEFAULTIGNORE))
    end
         
    # Push a parsed ignore list onto the stack.
    # 
    # @param directory the name of the directory, relative to its parent; '' for the outermost directory,
    #   or if it represents the same directory as its parent;
    #   should not include any path separators (/, \)
    # @param expr a list of IgnoreEntries
    def pushIgnoreList(directory, expr) 
       @ignoreStack.push([directory + '/', expr])
    end
    
    def popIgnoreList() 
      @ignoreStack.pop()
    end
      
    # Determine the secondary key, which is used for the filenames (not their contents)
    # This is found by encrypting the primary key.
    def prepareKeys() 
      
      key = @encrKey
      
      en = MyAES.new(true, key, "")
    
      en.finish(key)            
    
      key2 = en.flush()
      
      # Skip the nonce and header portions
      key2 = en.strip_encryption_header(key2)
      @encrKey2 = key2
    end
      
    # Encrypt a filename.
    # 
    # Encrypts using the alternate key, and ensures uses the hash code
    # of the (unencrypted) filename as the nonce.  This means the
    # encrypted version of a particular filename is always the same,
    # which is desirable.  
    # 
    # The security of the filename encryption is thus not as safe as that
    # of the original files (since the nonces are not guaranteed to be unique),
    # and is why we use a different key for them.
    # 
    # Encrypted filenames are also given a prefix to distinguish them
    # from files not created by this program (or filenames that have not been encrypted)
    # 
    # If filenames are not encrypted in this repository, returns filename unchanged.
    #
    def encryptFilename(s)   
      
      db = warndb 0
      !db || pr("\n\nencryptFilename %s\n",d(s))
      
      return s if @orignames
      
      nonce = OpenSSL::Digest::SHA1.new(s).digest
      !db || pr(" SHA1 applied, nonce=%s\n",dt(nonce))
      !db || hex_dump(nonce,"SHA1 nonce")
      
      bf = MyAES.new(true, @encrKey2, nonce)
      bf.finish(s)
      b = bf.flush()
      
      !db || hex_dump(b,"AES encrypted")
      
      s3 = Base64.urlsafe_encode64(b)
      !db || hex_dump(s3,"Base64 encoded")
      
      s2 = ENCRFILENAMEPREFIX.dup
      
      s2 << s3
      !db || pr("encr fname: %s\n",d(s2))
      
      s2
    end
    
    #  Decrypt a filename suffix; raises DecryptionError if unsuccessful
    def decryptFilenameAux(suffix)
      db = warndb 0
      !db || pr("decryptFilenameAux: %s\n",d(suffix))
      begin
        b = Base64.urlsafe_decode64(suffix)
        !db || hex_dump(b,"after base64 decode")
      
        bf = MyAES.new(false, @encrKey2)
        bf.finish(b)
        
        b = bf.flush()
        !db || hex_dump(b,"after decrypt")
      
        s = bytes_to_str(b)
        !db || hex_dump(s,"after cvt to string (#{s})")
      
      rescue ArgumentError => e
        raise DecryptionError.new(e) 
      end
      
      set_recovery_pwd_verified()
      
      return s
    end
  
    # Verify that a key is the correct password for this repository.
    # @param key key to verify
    # @param key_verifier an encrypted string that will decrypt correctly if the key is correct
    def verify_encrypt_pwd(key, key_verifier)
      db = warndb 0
      !db || pr("verify_encrypt_pwd key %s, verifier %s\n",d(key),hex_dump_to_string(key_verifier))

      if !MyAES.is_string_encrypted(key, key_verifier)
        raise(DecryptionError, "#{key} is not the correct password for this repository")
      end
    end
    
    def set_recovery_pwd_verified
      if !@recovery_pwd_verified
        @recovery_pwd_verified = true
      end
    end
    
    # Decrypt a filename; if filenames are not encrypted in this repository, 
    # If encrypted, and failed to decrypt, returns nil
    # returns unchanged
    def decryptFilename(s, assumeEncrypted=true) 
      db = warndb 0
      
      return s if (not assumeEncrypted) and @orignames
  
      if not s.start_with?(ENCRFILENAMEPREFIX) 
        raise ArgumentError, "Encrypted filename has unexpected prefix" 
      end
      
      !db || pr("decryptFilename %s\n",d(s) )
      s = s[ENCRFILENAMEPREFIX.size .. -1]
      decryptFilenameAux(s)
    end
  
      
    # Update a single source file if necessary (not a directory)
    def encrypt_file(sourceFile, encryptFile)
  
      # If encrypted file is a directory, delete it
      if File.directory?(encryptFile) 
        pth = rel_path(encryptFile, @outputDir) 
       
        if @verbosity >= 1 
          msg = "Encrypting file " + rel_path(sourceFile, @inputDir) + " is overwriting existing directory: " + pth
        end
        
        if not @dryrun 
          remove_file_or_dir(encryptFile)
        end
      end
      
      # Determine if existing encrypted version exists
      # and is up to date
      mustUpdate = (not File.file?(encryptFile))  \
                    or (File.mtime(encryptFile) < File.mtime(sourceFile))
      
      if mustUpdate 
        showProgress = (@verbosity >= 0)
        
        srcDisp = rel_path(sourceFile, @inputDir) 
        if showProgress 
          pr("%s", srcDisp) 
        end
        
        encPath = convertFile(sourceFile, true, showProgress, false)
        FileUtils.mv(encPath, encryptFile)
        
        
        if @verifyEncryption
          # Verify that the original and decoded files are identical
          decoded_file = convertFile(encryptFile,  false, showProgress, true)
          files_match = FileUtils.compare_file(sourceFile, decoded_file.path)
          decoded_file.unlink
          
          if !files_match
            delete_file_or_dir(encryptFile)
            raise EncryptionVerificationException, \
              "File '#{srcDisp}' did not encrypt/decrypt correctly" 
            
          end
          if @verbosity >= 0
            pr(" (file #{srcDisp} encrypted correctly)\n")
          end
        end
      end
    end
        
    # Determine if a file matches one of the expressions in the ignore stack.
    # Searches the stack from top to bottom (i.e., the outermost elements are examined last)
    def shouldFileBeIgnored(f)
      db = false
      !db || pr("shouldFileBeIgnored? #{f}\n")
      f2 = f
      @ignoreStack.reverse.each do |dir,ients|
        ients.each do |ient|
          fArg = ient.pathMode  ? f2 : f
          
          matches = ient.rexp.match(fArg) 
          !db || pr("  ent path=#{ient.pathMode} rexp=#{ient.rexp} neg=#{ient.negated} matches=#{matches}\n")
                  
          if matches 
            return !ient.negated 
          end
        end
        f2 = dir + f2
      end
      
      return false
    end
    
    # Get path relative to an absolute path
    # @param path 
    # @param abs_path  
    # @return path expressed relative to abs_path
    #
    def rel_path(path, abs_path)
      pth = Pathname.new(path)
      return pth.relative_path_from(Pathname.new(abs_path)).to_s
    end        
         
    # Examine all files in repository; reencrypt those that have changed 
    # (by comparing their time stamps with the time stamps of the encyrypted versions)
    def encryptDir(sourceDir, encryptDir)
      db = warndb 0
      !db || pr("\n\nencryptDir\n %s =>\n %s\n",d(sourceDir),d(encryptDir))
      
      # Add contents of .lencignore to stack.  If none exists, treat as if empty
      lst = []
      ignPath = File.join(sourceDir, IGNOREFILENAME)
      if File.file?(ignPath) 
        f1 = read_text_file(ignPath)
        lst = Repo.parseIgnoreList(f1, ignPath)
      end
      pushIgnoreList(File.basename(sourceDir), lst)
      
      # Create set of encrypted filenames that belong to this directory, so 
      # we can delete encrypted versions of files that are no longer in the source
      # directory.
      encFilenameSet = Set.new
      
      # If no encrypted directory exists, create one
      if not File.directory?(encryptDir) 
        if @verbosity >= 1 
            puts("Creating encrypted directory: " + d(rel_path(encryptDir, @outputDir)))
        end
        
        if not @dryrun
          if File.file?(encryptDir)
            pth = rel_path(encryptDir, @outputDir) 
            
            if @verbosity >= 1 
              pr("Encrypting directory is overwriting existing file: " + pth)
            end
                           
            remove_file_or_dir(encryptDir)
          end
          Dir.mkdir(encryptDir)
        end
      end
      
      # Examine each file in source dir
      dirc = dir_entries(sourceDir)
      
      dirc.each do |f2|
        # Convert string to ASCII-8BIT encoding.
        f = to_ascii8(f2)
        
        !db || pr(" testing if file should be ignored: #{f}\n")
        ignore = shouldFileBeIgnored(f)
        
        filePath = File.join(sourceDir,f)
        
        if File.symlink?(filePath)
          if @verbosity >= 0 
            pr("Omitting symlink file '#{rel_path(filePath,@inputDir)}'\n")
          end  
          next
        end
        
        if ignore 
          !db || pr("(ignoring %s)\n", rel_path(filePath, @inputDir)) if @verbosity >= 1 
          next
        end
        
        if f.start_with?(ENCRFILENAMEPREFIX) 
          if @verbosity >= 0 
            pr("(Omitting source file / dir with name that looks encrypted: #{d(f)})\n")
          end
        end
        
        encrName = encryptFilename(f)
        !db || pr(" encrypted filename %s => %s\n",d(f),d(encrName))
        
        if @verifyEncryption 
          decrName = decryptFilename(encrName, false)
          if !decrName || decrName != f 
            !db || pr("decrName encoding=#{decrName.encoding}\n f encoding=#{f.encoding}\n")
            !db || hex_dump(decrName,"decrName")
            !db || hex_dump(f,"f")
            
            raise EncryptionVerificationException, \
             "Filename #{f} did not encrypt/decrypt properly"
          end
          pr(" (filename #{f} encrypted correctly)\n") if @verbosity >= 0
        end
        
        encFilenameSet.add(encrName)
        encrPath = File.join(encryptDir, encrName)
        
        if File.directory?(filePath) 
          encryptDir(filePath, encrPath)
        else 
          !db || pr("...attempting to encrypt file #{filePath} to #{encrPath}...\n")
          encrypt_file(filePath, encrPath)
        end
      end
     
      # Truncate global ignore list to original length
      popIgnoreList()
      
      # Examine every file in encrypted directory; delete those that don't correspond to source dir
      
      # (if doing dry run, encrypt dir may not exist)
      
      !db || pr("examining files in encrypted dir #{encryptDir} to delete ones that don't belong\n")
      if File.directory?(encryptDir) 
        dire = dir_entries(encryptDir)
      else
        dire = []
      end
      
      dire.each do |f|
        next if not f.start_with?(ENCRFILENAMEPREFIX)
  
        if not encFilenameSet.member? f
          begin
            orphanOrigName = decryptFilename(f)
            next if !orphanOrigName
            orphanPath = File.join(encryptDir, f)
            if @verbosity >= 1 
              printf("Removing encrypted version of missing (or ignored) file " \
                    +  rel_path(File.join(sourceDir, orphanOrigName), @inputDir) + ": " + orphanPath) 
            end
            if !@dryrun 
              remove_file_or_dir(orphanPath)
            end
          rescue DecryptionError 
            # ignore...
          end
        end
      end
    end
        
      
    # Decrypt all files (and, recursively, folders) within a directory to _recover folder
    def recover(encryptDir, recoverDir) 
      db = warndb 0
      !db || pr("recover enc_dir %s\n   recoverDir %s\n",d(encryptDir),d(recoverDir))
      
      # If no _recover directory exists, create one
      if not File.directory?(recoverDir)
        if File.file?(recoverDir)
          raise RecoveryError, "Cannot replace existing file '" + recoverDir + "' with directory" 
        end
        Dir.mkdir(recoverDir) if not @dryrun
      end
        
      if not File.directory?(encryptDir)
        raise ArgumentError, "encrypt dir not found"
      end
      
      # Examine each file in encrypt dir
      dirc = dir_entries(encryptDir)
      !db || pr("files in encrypt dir=%s\n",d2(dirc))
        
      dirc.each do |f|
        
        !db || pr("...file=%s\n",d(f))
        if shouldFileBeIgnored(f)
          if @verbosity >= 1 
            pr("(ignoring %s)\n", rel_path(f, @inputDir)) 
          end
          next
        end
        
        # Only decrypt the filename if it is actually encrypted
        origName = f
        if origName.start_with?(ENCRFILENAMEPREFIX)
          begin
            decrName = decryptFilename(origName, true)
          rescue DecryptionError
            encPath = File.absolute_path(File.join(encryptDir,f))
            pth = rel_path(encPath, @inputDir)
            if !@recovery_pwd_verified
              raise(DecryptionError,"Wrong password (cannot decrypt filename #{pth})")
            end
                          
            if @verbosity >= 0
              puts "Unable to decrypt filename: #{pth}"
            end
            next
          end
          origName = decrName
        end
        origPath = File.join(recoverDir, origName)
        encrFullPath = File.join(encryptDir, f)
        
  
        # If decrypted version already exists, and is more recent than the 
        # encrypted one, don't restore it.
        
        if File.file?(encrFullPath) && File.file?(origPath) \
            && File.mtime(origPath) >= File.mtime(encrFullPath) 
          if @verbosity >= 1 
            puts(" " + rel_path(origPath,@outputDir) + " (still valid)")
          end
          next
        end
  
        if File.directory?(encrFullPath) 
          recover(encrFullPath, origPath)
        else 
          pth = rel_path(origPath, @outputDir)
          showProgress = @verbosity >= 0
          if showProgress
            pr("%s", pth)
          end
          begin
            tmp_file = convertFile(encrFullPath,false, showProgress)
            
            set_recovery_pwd_verified()
            
            if not @dryrun
              if File.file?(origPath) 
                  remove_file_or_dir(origPath)
              end
              FileUtils.mv(tmp_file.path, origPath)
            else
              tmp_file.unlink
            end
            
          rescue DecryptionError => e
                        
            if !@recovery_pwd_verified
              raise(DecryptionError,"Wrong password (cannot decrypt file #{pth})")
            end
            
            if @verbosity >= 0
              msg = "Unable to decrypt file: #{pth} (cause: #{e.message})"
              pr("\n%s\n", msg)
            end
          end
        end
      end
    end
  
    # Encrypt or decrypt a file (not a directory)
    # @param srcPath source path
    # @param encrypt true if encrypting
    # @return temporary file containing modified file
    #
    def convertFile(srcPath,encrypt, showProgress=false, verifying=false) 
  
      db = warndb 0
      !db||pr("\n\n\n\nconvertFile\n %s\n",d(srcPath))
      
      fw = nil
      showDots = false
      if not @dryrun 
        
        fSize = File.size(srcPath)
        
        fr = File.open(srcPath, 'rb')
        fw = Tempfile.new("repo")
        
        cSize = 100000
        
        # Predict number of chunks required
        chunksRemaining = [1, (fSize / cSize.to_f + 0.5).to_i].max
        dotSize = 30
        !db || pr(" fSize=%d, chunksRem=%d\n",fSize,chunksRemaining)
        
        showDots = showProgress && chunksRemaining >= dotSize
        !db || (showDots = false)
        
        if showDots and verifying 
          pr(" verifying:")
        end
          
        !db || pr("\n encrKey=%s\n",dt(@encrKey))
        
        bf = MyAES.new(encrypt, @encrKey)
          
        proc = 0
        
        pr(" [") if showDots 
          
        last = false
        while not last  
          
          if showDots and (chunksRemaining % dotSize) == 0 
            pr(".")
          end
          chunksRemaining -= 1
            
          chunkSize = fSize - proc
          last = true
          
          if chunksRemaining > 0
            last = false
            chunkSize = cSize
          end
            
          proc += chunkSize
          chunk = fr.read(chunkSize)
          
          if (!chunk) or chunk.size != chunkSize 
            raise IOError,"Failed to read bytes from file"
          end
          
          bf.add(chunk)
          if last 
            bf.finish()
          end
          fw.write(bf.flush())
        end
        
        fr.close()
        fw.close()
        
        pr("]") if showDots 
        
      end 
          
      if showProgress and (showDots or not verifying) 
        pr("\n")
      end
      
      fw
    end
    
  end # class Repo
 
end # module LEnc
