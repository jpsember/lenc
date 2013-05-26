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
  end
end


module LEnc

  KEY_LEN_MIN = 8
  KEY_LEN_MAX = 56
  
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
    
    
    # We now ignore 'dot-underscore' files which OSX seems to create sometimes
    # to store additional information about other files.
    
    DEFAULTIGNORE = \
      "#{LENC_REPO_FILENAME}\n " \
       ".DS_Store\n" + \
       "._*\n" + \
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
    
    # If a password hasn't been defined, ask user for one.
    # Also, pad password out to some minimum size  
    #
    def define_password(pwd)
      if !pwd
        
        if true
          
          # Use the 'highline' gem to allow typing password without echo to screen
          require 'rubygems'
          require 'highline/import'
          pwd = ask("Password: ") {|q| q.echo = false}
            
        else
          printf("Password: ")
          pwd = gets
        end
        
        if pwd
          pwd.strip!
          pwd = nil if pwd.size == 0
        end
        if !pwd
          raise DecryptionError, "No password given"
        end
      end
      
      while pwd.size < KEY_LEN_MIN
        pwd *= 2
      end
      pwd
    end
    
    
    # Create a new encryption repository, and open it. 
    # 
    # @param repo_dir directory of new repository (nil for current directory)
    # @param key      encryption key, a string from KEY_LEN_MIN to KEY_LEN_MAX characters in length
    # @param enc_dir  if not nil, directory to store encrypted files; must not yet exist, and must
    #                   not represent a directory lying within the repo_dir tree;
    #                 if nil, repository will be encrypted in-place
    # @param original_names  if true, the filenames are not encrypted, only the file contents
    # @raise ArgumentError if appropriate
    #
    def create(repo_dir, key, enc_dir, original_names=false) 
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
      
      @confFile.set('orignames', @orignames)
      
      if @verbosity >= 1 
          pr("Creating encryption repository %s\n", @confFile.path)
      end
      
      edir = nil
      if enc_dir
        edir = File.absolute_path(enc_dir)
        pp = verifyDirsDistinct([repo_dir, edir])

        if pp
          raise ArgumentError, "Directory " + pp[0] + \
          " is a subdirectory of " + pp[1]
        end
        
        if File.exists?(edir)
          raise ArgumentError, \
          "Encryption directory or file already exists: '#{edir}'"
        end
        @confFile.set('enc_dir', edir)
      end

      key = define_password(key)
      if (key.size < KEY_LEN_MIN || key.size > KEY_LEN_MAX) 
        raise ArgumentError, "Password length " + key.size.to_s \
          + " is illegal" 
      end
      
      # Construct a string that verifies the password is correct
      en = MyAES.new(true, key  )
      en.finish("!!!")            
      verifier_string = en.flush

      # Store key verifier as an array of bytes, to avoid nonprintable problems
      vs2 = Base64.urlsafe_encode64(verifier_string)
      @confFile.set('key_verifier', vs2)
      
      if not @dryrun 
        if edir
          Dir.mkdir(edir)
        end
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
    def open(startDirectory = nil, password = nil) 
      db = warndb 0
      !db || pr("Repo.open startDir=%s, password=%s\n",d(startDirectory),d(password))
        
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
      pwd = define_password(password)
      
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
   
    # Encrypt repository's files.
    # If repo is dual, finds files that need to be re-encrypted and does so.
    # If singular, encrypts all those files that are not yet encrypted.
    #
    # Repository must be open.
    #     
    # @raise IllegalStateException if repository isn't open.
    # 
    def perform_encrypt()
      db = warndb 0
      raise IllegalStateException if @state != STATE_OPEN
      
      enc_dir = @encrDir
      if in_place?
        enc_dir = @repoBaseDir
        !db || pr("perform_encrypt, enc_dir set to repoBaseDir #{@repoBaseDir}\n")
      end
      
      setInputOutputDirs(@startDir,enc_dir)
      
      # If encrypting singular repository, ignore all .lencignore files
      if in_place?
        pushIgnoreList('', Repo.parseIgnoreList(".lencignore"))
      end
      
      puts("Encrypting...") if @verbosity >= 1

      begin
        encrypt_directory_contents(@repoBaseDir, enc_dir)
        puts("...done.") if @verbosity >= 1
      end
    end
         
    # Decrypt files within singular repository.
    # Repository must be open.
    #
    # @raise IllegalStateException if repository isn't open.
    #
    def perform_decrypt()
      raise IllegalStateException if (@state != STATE_OPEN || !in_place?)

      enc_dir = @repoBaseDir

      setInputOutputDirs(enc_dir,enc_dir)

      puts("Decrypting...") if @verbosity >= 1

      begin
        decrypt_directory_contents(enc_dir)
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
      
      key = define_password(key)
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
       
    def in_place?
      !@encrDir
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
    # If the given filename already has this prefix, it is assumed that the filename has
    # already been encrypted.
    #
    # If filenames are not encrypted in this repository, returns filename unchanged.
    #
    def encryptFilename(s)   
      
      db = warndb 0
      !db || pr("\n\nencryptFilename %s\n",d(s))
      
      return s if @orignames
      
      return s if s.start_with?(ENCRFILENAMEPREFIX) 
      
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
        raise(DecryptionError, "incorrect password")
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
    # @param sourceFile absolute path of source file
    # @param encryptFile absolute path of encrypted file
    #
    def encrypt_file(sourceFile, encryptFile)
  
      db = warndb 0
      !db || pr("encrypt_file\n source=#{sourceFile}\n encrypt=#{encryptFile}\n")
      
      # If encrypted file is a directory, delete it.  This can only occur if it's a dual repository.
      if File.directory?(encryptFile) 
        raise IllegalStateError if in_place?
        
        pth = rel_path(encryptFile, @outputDir) 
       
        if @verbosity >= 1 
          msg = "Encrypting file " + rel_path(sourceFile, @inputDir) \
              + " is overwriting existing directory: " + pth
        end
        
        if not @dryrun 
          remove_file_or_dir(encryptFile)
        end
      end
      
      # Determine if existing encrypted version exists
      # and is up to date; only if not in-place
      mustUpdate = in_place? || ((not File.file?(encryptFile))  \
                    or (File.mtime(encryptFile) < File.mtime(sourceFile)))
      
      if mustUpdate 
        showProgress = (@verbosity >= 0)
        
        srcDisp = rel_path(sourceFile, @inputDir) 
        if showProgress 
          pr("%s", srcDisp) 
        end
        
        temp_enc_path = convertFile(sourceFile, true, showProgress)
        !db || pr(" converted [#{sourceFile}] to temp [#{temp_enc_path}]\n")
        if not @dryrun
          FileUtils.mv(temp_enc_path, encryptFile)
          !db || pr("  moved temp to encryptFile #{encryptFile}\n")
        end
        
      end
    end
        
    # Determine if a file matches one of the expressions in the ignore stack.
    # Searches the stack from top to bottom (i.e., the outermost elements are examined last)
    # @param name_only filename, without path
    # @param full_path full path of file
    #
    def should_file_be_ignored(name_only, full_path)
      db = warndb 0
      !db || pr("should_file_be_ignored? #{name_only}\n")
      
      # Let f2 be the filename including the directories corresponding
      # to the ignore stack
      
      f2 = name_only
      
      @ignoreStack.reverse.each do |dir,ients|
        ients.each do |ient|
          
          if ient.dirOnly && !File.directory?(full_path)
            next
          end
            
          fArg = ient.pathMode  ? f2 : name_only
          
          matches = ient.rexp.match(fArg) 
          !db || pr("  ent path=#{ient.pathMode} rexp=#{ient.rexp} neg=#{ient.negated} matches=#{matches}\n")
                  
          if matches 
            return !ient.negated 
          end
        end
        f2 = File.join(dir,f2)
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
    #
    # @param sourceDir  absolute path of source directory
    # @param encryptDir absolute path of encryption directory
    #
    def encrypt_directory_contents(sourceDir, encryptDir)
      
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
      # Don't do this if repo is in-place.
      encFilenameSet = nil
      if !in_place?
        in_place? || encFilenameSet = Set.new
      end
      
      # If no encrypted directory exists, create one
      if !in_place? && !File.directory?(encryptDir) 
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
      
      !db || pr(" dirc=%s\n",d2(dirc))
      dirc.each do |f2|
        # Convert string to ASCII-8BIT encoding.
        f = to_ascii8(f2)
        
        filePath = File.join(sourceDir,f)
        
        if File.symlink?(filePath)
          if @verbosity >= 0 
            pr("Omitting symlink file '#{rel_path(filePath,@inputDir)}'\n")
          end  
          next
        end
        
        !db || pr(" testing if file should be ignored: #{f}\n")
        if should_file_be_ignored(f, filePath)
          !db || pr("(ignoring %s)\n", rel_path(filePath, @inputDir)) if @verbosity >= 1 
          next
        end
        
        # If we're doing in-place encryption, file is not a directory, and it's already encrypted, ignore
        if in_place?
          next if (!File.directory?(filePath) && f.start_with?(ENCRFILENAMEPREFIX))
          next if (@orignames && MyAES.is_file_encrypted(@encrKey,filePath))
        else
          if f.start_with?(ENCRFILENAMEPREFIX) 
            if @verbosity >= 0 
              pr("(Omitting source file / dir with name that looks encrypted: #{d(f)})\n")
            end
            next
          end
        end
        
        
        if !in_place?
          encrName = encryptFilename(f)
          !db || pr(" encrypted filename %s => %s\n",d(f),d(encrName))
          encFilenameSet.add(encrName)
          encrPath = File.join(encryptDir, encrName)
          
          if File.directory?(filePath) 
            encrypt_directory_contents(filePath, encrPath)
          else 
            !db || pr("...attempting to encrypt file #{filePath} to #{encrPath}...\n")
            encrypt_file(filePath, encrPath)
          end
        
        else
          
          encrPath = filePath
          if !@origNames
            encrName = encryptFilename(f)
            encrPath = File.join(sourceDir, encrName)
          end
          
          if File.directory?(filePath) 
            encrypt_directory_contents(filePath, filePath)
            # Rename the directory to its encrypted form, if necessary
            if (not @dryrun) && (filePath != encrPath)  
              !db || pr(" renaming now-encrypted file from\n  #{filePath}\n to\n  #{encrPath}\n")
              FileUtils.mv(filePath,encrPath)
            end
          else
            encrypt_file(filePath, encrPath)
            # Delete unencrypted file, if not using original names
            if (not @dryrun) && (not @orignames)
              !db || pr(" attempting to remove unencrypted file #{filePath}\n")
              FileUtils.rm(filePath)
            end
          end
        end
        
      end
     
      # Truncate global ignore list to original length
      popIgnoreList()
      
      if !in_place?
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
              if not @dryrun
                remove_file_or_dir(orphanPath)
              end
            rescue DecryptionError
              # ignore...
            end
          end
        end
      end
    end
    
    # Decrypt all files recursively within singular repository subdirectory
    #
    # @param encr_dir_path  absolute path of encrypted directory
    # @param decr_dir_name  absolute path of directory after decrypting (used for display purposes only);
    #   if nil, uses encrypted directory name
    #
    def decrypt_directory_contents(encr_dir_path,decr_dir_name = nil)

      decr_dir_name ||= encr_dir_path
      
      db = warndb 0

      !db || pr("\n\ndecrypt_directory_contents: %s (orignames=#{@orignames})\n",d(encr_dir_path))

      # Examine each file in source dir
      dirc = dir_entries(encr_dir_path)

      dirc.each do |f2|
        # Convert string to ASCII-8BIT encoding.
        f = to_ascii8(f2)

        filePath = File.join(encr_dir_path,f)
        if File.symlink?(filePath)
          if @verbosity >= 0
            pr("Omitting symlink file '#{rel_path(filePath,@inputDir)}'\n")
          end
          next
        end

        !db || pr(" filePath=#{filePath}\n")
        decrPath = filePath
        decrName = f
        if @orignames
          if File.file?(filePath)
            if !MyAES.is_file_encrypted(@encrKey,filePath)  
              !db || pr(" file is not encrypted, skipping\n")
              next
            end
          end  
        else
          next if !f.start_with?(ENCRFILENAMEPREFIX)
          begin
            decrName = decryptFilename(f)
            decrPath = File.join(encr_dir_path, decrName)
          rescue DecryptionError => e
            puts "Unable to decrypt filename #{f}"
            next
          end
        end

        if File.directory?(filePath)
          decrypt_directory_contents(filePath, File.join(decr_dir_name, decrName))
          # Rename the directory to its decrypted form, if filenames are to be encrypted
          if !@orignames
            raise ArgumentError,"decrypted already exists: #{decrPath}" \
                          if File.exist?(decrPath)
            
            if not @dryrun            
              !db || pr(" renaming now-decrypted directory from\n  #{filePath}\n to\n  #{decrPath}\n")
              FileUtils.mv(filePath,decrPath)
            end
          end
        else
          decrPathDisp = File.join(decr_dir_name,decrName)
          pth = rel_path(decrPathDisp, @repoBaseDir)
          showProgress = @verbosity >= 0
          if showProgress
            pr("%s", pth)
          end
          begin
            tmp_file = convertFile(filePath, false, showProgress)
            if !@orignames
              raise ArgumentError,"decrypted file or directory already exists: #{decrPath}" \
              if File.exist?(decrPath)
            end
               
            if not @dryrun
              remove_file_or_dir(decrPath)
              FileUtils.mv(tmp_file.path, decrPath)
              # Remove the encrypted version, if we aren't using original names
              if !@orignames
                FileUtils.rm(filePath)
              end
            else
              tmp_file.unlink
            end

          rescue DecryptionError => e
            if @verbosity >= 0
              msg = "Unable to decrypt file: #{pth} (cause: #{e.message})"
              pr("\n%s\n", msg)
            end
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
        if not @dryrun
          Dir.mkdir(recoverDir) 
        end
      end
        
      if not File.directory?(encryptDir)
        raise ArgumentError, "encrypt dir not found"
      end
      
      # Examine each file in encrypt dir
      dirc = dir_entries(encryptDir)
      !db || pr("files in encrypt dir=%s\n",d2(dirc))
        
      dirc.each do |f|
        
        !db || pr("...file=%s\n",d(f))
          
        encrFullPath = File.join(encryptDir, f)
                
        if should_file_be_ignored(f, encrFullPath)
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
    def convertFile(srcPath,encrypt, showProgress=false) 
  
      db = warndb 0
      !db||pr("\n\n\n\nconvertFile\n %s\n",d(srcPath))
      
      fw = nil
      showDots = false
      if not @dryrun 
        
        fSize = File.size(srcPath)
        
        fr = File.open(srcPath, 'rb')
        fw = Tempfile.new("repo")
        !db || pr("created temporary file #{fw.path}\n")
        cSize = 100000
        
        # Predict number of chunks required
        chunksRemaining = [1, (fSize / cSize.to_f + 0.5).to_i].max
        dotSize = 30
        !db || pr(" fSize=%d, chunksRem=%d\n",fSize,chunksRemaining)
        
        showDots = showProgress && chunksRemaining >= dotSize
        !db || (showDots = false)
        
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
          
      if showProgress 
        pr("\n")
      end
      
      !db || pr(" (done convertFile)\n")
      fw
    end
    
  end # class Repo
 
end # module LEnc
