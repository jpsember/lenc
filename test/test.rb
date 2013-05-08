require 'test/unit'

require_relative '../lib/lenc/tools.rb'
req('repo lencrypt')


#SINGLETEST = "test_121_update_repo_with_lencrypt_program"
if defined? SINGLETEST
  if main?(__FILE__)
    ARGV.concat("-n  #{SINGLETEST}".split)
  end
end

# Enable to display verbose output
#ARGV.concat("-v")


class RepoTest < MyTestSuite

  include LEnc
  
  # Make a directory, if it doesn't already exist
  def mkdir(name)
    if !File.directory?(name)  
      Dir::mkdir(name)
    end
  end

  def suite_setup
    #    pr("\n\n>>>> RepoTest   setup\n\n")
    
    # Make current directory = the one containing this script
    main?(__FILE__)
    
    @@testDir = "__temp_dirs__"
    mkdir(@@testDir)
      
    @@sourceDir = File.join(@@testDir,"__source__")
    @@sourceDir2 = File.join(@@testDir,"ip")
    @@encryptDir = File.join(@@testDir,"__encrypted__")
    @@recoverDir = File.join(@@testDir,"__recovered__")
    @@repoFile = File.join(@@sourceDir,Repo::LENC_REPO_FILENAME)
    @@key = "onefishtwofishredfishbluefish"
    @@sampleFile = "demeter"
    
    if !File.directory?(@@sourceDir)
      create_source_tree()
    end

    clean()
    
    # Construct a list of the source subdirectories, since some of them have
    # unicode filenames and OSX changes them on us.
    @@sourceDirs = []
    getSourceDirList(@@sourceDirs, @@sourceDir)
  end

    
  def getSourceDirList(lst, dr)  
    dir_entries(dr).each do |f|
      child = File.join(dr,f)
      if File.directory? child
        lst.push child
        getSourceDirList(lst, child)
      end
    end
  end
  
    
  # Delete .lenc file from source directory,
  # and delete the encryption and recovery directories
  def clean
#    pr("clean, repoFile=%s exists=%s\n",@@repoFile,File.file?(@@repoFile))
    remove_file_or_dir(@@repoFile)
    remove_file_or_dir(@@encryptDir)
    remove_file_or_dir(@@recoverDir)
#    remove_file_or_dir(bogusSourceFile())
  end
  
  
  def suite_teardown
#    pr("\n\n<<<< RepoTest   teardown\n\n")
    
    if false
      warn("always removing source dir")
      
      if @@sourceDir.end_with?("__source__")
        pr("removing...\n")
        remove_file_or_dir(@@sourceDir)
      end
    end
  end
  
  def method_setup
#    pr("\n\n\n")
  end
  
  def method_teardown
#    pr("\n\n\n")
  end

      
    
  def makeFile(pth, lngth=3)  
    remove_file_or_dir(pth)
    
    srand(1965)
    
    File.open(pth, 'wb')  do |f|
      j = 0
      while j < lngth  
        if (j+1) % 40 == 0
            f.write("\n")
        else
            f.write((rand(26)+65).chr)
        end
        j += 1
      end
    end
  end
     
  def unicode(c)
    s = [c].pack("U*")
    s
  end
    
  def create_source_tree  
    # Create a set of directories and files within the repo's source directory.
    
    # Specify a script as a sequence of names, each followed by
    #  | : file
    #  / : directory
    #  ^ : parent directory (name should be empty)
    
    # Some names have unicode characters for test purposes.
    
    scr =<<SCR
   
    mars| sol| luna| aphrodite | apollo | ares | artemis | hades | demeter |
    alpha/ 
       earth| venus| symphony 1 | symphony 2 | hephaestus | hera | hermes | hestia |
       delt#{unicode(0xe5)} / 
          jupiter| saturn| poseidon | zeus | 
       ^ 
    ^ 
    bet#{unicode(0xe1)} gamma|
      uranus|
      neptune|
      pluto|
SCR
      
    # Script of predetermined file lengths:
    cs = RepoInternal::CHUNK_SIZE_ENCR
    hs = RepoInternal::CHUNK_HEADER_SIZE
    flens = [0, cs - 1, cs, cs + 1, cs + hs - 1, cs + hs, cs + hs + 1,
      (2 * cs) - 1, 2 * cs, 2 * cs + 1, 2 * (cs + hs) - 1, 2 * (cs + hs), 2 * (cs + hs) + 1]
    fNum = 0

    srand(1983)

    dr = @@sourceDir
    mkdir(dr)

    dirStack = []
    k = 0
    k0 = k
    while k < scr.size
      c = scr[k]
      k += 1
      next if !"|/^".index(c)

      nm = scr[k0...k-1].strip

      k0 = k

      if c == '|'
        # create a file; use our predetermined lengths, if we still have some;
        # otherwise, choose a random file length
        if fNum < flens.size
          j = flens[fNum]
        else
          j = (rand() * rand() * 130000).to_i + 3
        end

        # Make the length end with a particular sequence of digits so we can quickly determine whether
        # file has been encrypted or decrypted
        q = (j - 11) % 100
        j -= q
        j += 100 if j <= 0

        fNum += 1
        makeFile(File.join(dr, nm), j)
      elsif c == '/'
        dirStack.push(dr)
        dr = File.join(dr,nm)
        mkdir(dr)
      elsif c == '^'
        dr = dirStack.pop
      end
    end

      # Store some .lencignore files
    dr = @@sourceDir
    writeIgnore(dr, "s*")
    
    dr = File.join(dr, "alpha")
    writeIgnore(dr, "hera")
    
    dr = File.join(dr, "delt#{unicode(0xe5)}")
    writeIgnore(dr, "!s*")
  end


  # Create in-place source tree as copy of normal source tree
  def create_source_tree2
    if !File.exist?(@@sourceDir2)
      remove_file_or_dir(@@sourceDir2)
      FileUtils.cp_r(@@sourceDir,@@sourceDir2)
    end
    remove_file_or_dir(File.join(@@sourceDir2,".lenc"))
  end
  

  
  
  def writeIgnore(dr, contents)  
    pth = File.join(dr,Repo::IGNOREFILENAME)
    File.open(pth,'w') do |f|
      f.write("# This is a .lencignore file\n#{contents}\n\n### end ###\n")
    end
  end
      
  def ex(args)  
    if args.is_a? String
      args = args.split
    end
    args.concat(["-w", @@sourceDir])
    args.concat(["-q"])
    LEncApp.new().run(args)
  end
  
#  def bogusSourceFile  
#    return File.join(@@sourceDir, "_#bogusfile.txt")
#  end

  def build_repo_obj(silent = true)
    v = silent ? -1 : 0
    rp = Repo.new(:verbosity => v)
    rp
  end
    
  def create_repo
    clean
    rp = build_repo_obj
    rp.create(@@sourceDir,@@key,@@encryptDir, true)
    rp.close  
    rp
  end
  
  def update_repo(silent = true)
    rp = build_repo_obj(silent)
    rp.open(@@sourceDir,@@key)
    rp.perform_encrypt
    rp.close  
  end
  
  def do_recover
    rp = build_repo_obj
    rp.perform_recovery(@@key, @@encryptDir, @@recoverDir)
    rp.close
  end
  
  # --------------- tests --------------------------
  
  
  
  def test_050_AES_encryption
    req 'aes'
          
    f = RepoInternal::MyAES.new(true, @@key, "42")
          
    originalText = ""
    while originalText.size < 100000
      64.times do |i|
        ch = ((i % 26) + 65).chr
        originalText << ch * 17
      end
    end
    
    enc = ""
    s = originalText.size
    n = 0
    while n < s 
      c = [60,s-n].min
      f.add(originalText[n...n+c])
      n += c
      enc << f.flush()
    end
          
    f.finish()
    enc << f.flush
     
    require 'digest/md5'
  
    digest = Digest::MD5.hexdigest(enc)
    assert(digest.to_s == '284740fbf3355951e9e76fb43fda985c')

    f = RepoInternal::MyAES.new(false, @@key)
    dec = ""
    n = 0
    s = enc.size
    while n < s 
      c = [60,s-n].min
      f.add(enc[n...n+c])
      n += c
      dec << f.flush
    end
    
    f.finish()
    dec << f.flush
    assert(originalText == dec)
  end
  
  
  # Create repo using Repo class
  def test_100_create_repo
    create_repo
    assert(File.file?(@@repoFile))
  end
  
  # Create repo using lencrypt program
  def test_101_create_repo_with_lencrypt_program
    clean
    a = "--init #{@@encryptDir} --key #{@@key}"
    ex(a)
  end

  def test_101_update_repo_with_verify
    clean
    ex("--init #{@@encryptDir} --key #{@@key}")
    rp = build_repo_obj
    rp.open(@@sourceDir,@@key)
    rp.perform_encrypt()
    rp.close  
  end

  def test_110_open_repo_using_Repo_class
    # (assumes repo exists at this point; preceding test creates it)
    rp = build_repo_obj
    rp.open(@@sourceDir,@@key)
  end

  def test_120_update_repo_using_Repo_class
    update_repo
    assert(File.directory?(@@encryptDir))
  end
  
  def test_121_update_repo_with_lencrypt_program  
    create_repo
    remove_file_or_dir(@@encryptDir)
    
     ex("--key #{@@key}")
    
    assert(File.directory?(@@encryptDir))
  end

  def test_125_recover_repository
    remove_file_or_dir(@@recoverDir)
    do_recover
    assert(File.directory?(@@recoverDir))  
  end
  
  def test_130_update_when_repository_not_found  
    assert_raise(RepoNotFoundException) do 
      clean
      rp = build_repo_obj
      rp.open(@@sourceDir)
    end
  end
  
  
  def test_200_recover_with_incorrect_password   
    create_repo
    ex("--key #{@@key}") # updates repo
    assert_raise(DecryptionError) do
      remove_file_or_dir(@@recoverDir)
      rp = build_repo_obj()
      rp.perform_recovery("thisisthewrongkey_______", @@encryptDir,@@recoverDir)
      rp.close
    end
  end
  
  def test_300_singular_repo
    create_source_tree2
    
    # Create in-place repository
    rp = build_repo_obj
    rp.create(@@sourceDir2,@@key,nil)
    rp.close  

    # Update the repo
    rp = build_repo_obj   
    rp.open(@@sourceDir2, @@key)
    rp.perform_encrypt()
    rp.close
    
       
  end
  
def test_310_singular_encrypt_then_decrypt
  
  create_source_tree2
  
  # Create in-place repository
  rp = build_repo_obj
  rp.create(@@sourceDir2,@@key,nil)
  rp.close  

  # Update the repo
  rp = build_repo_obj
  rp.open(@@sourceDir2, @@key)
  rp.perform_encrypt()
  rp.close
  
  # Try decrypting
  rp = build_repo_obj
  rp.open(@@sourceDir2, @@key)
  rp.perform_decrypt()
  rp.close
end

  
end
