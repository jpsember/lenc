#!/usr/bin/env ruby

require 'js_base/test'
require 'lenc'

class RepoTest < Test::Unit::TestCase

  include LEnc

  def setup
    # Create a test directory, if necessary; but don't delete it
    enter_test_directory('__test_repo_directory__')
    # @testDir = File.join(File.dirname(__FILE__),"__test_repo_directory__")
    # mkdir(@testDir)

    @sourceDir = 'repo1'
    @sourceDir2 = 'repo2'
    @encryptDir = "__encrypted__"
    @recoverDir = "__recovered__"
    @repoFile = File.join(@sourceDir,Repo::LENC_REPO_FILENAME)
    @repoFile2 = File.join(@sourceDir2,Repo::LENC_REPO_FILENAME)

    @key = "onefishtwofishredfishbluefish"
    @sampleFile = "demeter"

    if !File.directory?(@sourceDir)
      create_source_tree(@sourceDir)
    end

    cleanup
  end

  def cleanup
    FileUtils.rm_rf(@encryptDir)
    FileUtils.rm_rf(@recoverDir)
    FileUtils.rm_rf(@repoFile)
    FileUtils.rm_rf(@sourceDir2)
  end

  def teardown
    cleanup
    leave_test_directory(true)
  end

  def makeFile(pth, lngth=3)
    FileUtils.rm_rf(pth)

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

  def create_source_tree(source_dir)
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

    dr = source_dir
    FileUtils.mkdir_p(dr)

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
        FileUtils.mkdir_p(dr)
      elsif c == '^'
        dr = dirStack.pop
      end
    end

      # Store some .lencignore files
    dr = source_dir
    writeIgnore(dr, "s*")

    dr = File.join(dr, "alpha")
    writeIgnore(dr, "hera")

    dr = File.join(dr, "delt#{unicode(0xe5)}")
    writeIgnore(dr, "!s*")
  end


  # Create in-place source tree as copy of normal source tree
  def create_source_tree2
    if !File.exist?(@sourceDir2)
      FileUtils.rm_rf(@sourceDir2)
      FileUtils.cp_r(@sourceDir,@sourceDir2)
    end
    # Remove any existing repository file
    FileUtils.rm_rf(@repoFile2)
  end

  def writeIgnore(dr, contents)
    pth = File.join(dr,Repo::IGNOREFILENAME)
    File.open(pth,'w') do |f|
      f.write("# This is a .lencignore file\n#{contents}\n\n### end ###\n")
    end
  end

  def ex(args, using_script = true)
    if args.is_a? String
      args = args.split
    end
    args.concat(["-w", @sourceDir])
    args.concat(["-q"])

    if using_script
      cmd = 'lencrypt ' + args.join(' ')
      scall(cmd,false)
    else
      LEncApp.new().run(args)
    end
  end

  def build_repo_obj
    Repo.new(:verbosity => -1)
  end

  def create_repo
    rp = build_repo_obj
    rp.create(@sourceDir,@key,@encryptDir, true)
    rp.close
    rp
  end

  def update_repo
    rp = build_repo_obj
    rp.open(@sourceDir,@key)
    rp.perform_encrypt
    rp.close
  end

  def do_recover
    rp = build_repo_obj
    rp.perform_recovery(@key, @encryptDir, @recoverDir)
    rp.close
  end

  def create_repo_using_program
    a = "--init #{@encryptDir} --key #{@key}"
    ex(a)
  end


  # --------------- tests --------------------------


  def test_101_create_repo_with_lencrypt_program
    create_repo_using_program
  end

  def test_update_repo_with_verify
    ex("--init #{@encryptDir} --key #{@key}")
    rp = build_repo_obj
    rp.open(@sourceDir,@key)
    rp.perform_encrypt()
    rp.close
  end

  def test_open_repo_using_Repo_class
    create_repo
    rp = build_repo_obj
    rp.open(@sourceDir,@key)
  end

  def test_update_repo_using_Repo_class
    create_repo
    update_repo
    assert(File.directory?(@encryptDir))
  end

  def test_update_repo_with_lencrypt_program
    create_repo
    ex("--key #{@key}")
    assert(File.directory?(@encryptDir))
  end

  def test_recover_repository
    create_repo
    ex("--key #{@key}")
    do_recover
    assert(File.directory?(@recoverDir))
  end

  def test_update_when_repository_not_found
    assert_raise(RepoNotFoundException) do
      rp = build_repo_obj
      rp.open(@sourceDir)
    end
  end

  def test_update_when_repository_not_found_script
    cmd = "lencrypt -w #{@sourceDir} -q -k #{@key}"
    outp,success = scall(cmd,false)
    assert_equal(success,false)
    assert(outp.length < 100,"keep these messages small")
  end

  def test_recover_with_incorrect_password
    create_repo
    ex("--key #{@key}")
    assert_raise(DecryptionError) do
      FileUtils.rm_rf(@recoverDir)
      rp = build_repo_obj()
      rp.perform_recovery("thisisthewrongkey_______", @encryptDir,@recoverDir)
      rp.close
    end
  end

  def test_recover_with_incorrect_password_script
    create_repo
    ex("--key #{@key}")
    cmd = "lencrypt -r #{@encryptDir} #{@recoverDir} -q -k thisisthewrongkey_______"
    outp,success = scall(cmd,false)
    assert_equal(success,false)
    assert(outp.length < 100,"keep these messages small")
  end

  def test_singular_repo
    create_source_tree2

    # Create in-place repository
    create_source_tree2
    rp = build_repo_obj
    rp.create(@sourceDir2,@key,nil)
    rp.close

    # Update the repo
    rp = build_repo_obj
    rp.open(@sourceDir2, @key)
    rp.perform_encrypt()
    rp.close
  end

  def test_singular_encrypt_then_decrypt

    create_source_tree2

    # Create in-place repository
    create_source_tree2
    rp = build_repo_obj
    rp.create(@sourceDir2,@key,nil)
    rp.close

    # Update the repo
    rp = build_repo_obj
    rp.open(@sourceDir2, @key)
    rp.perform_encrypt()
    rp.close

    # Try decrypting
    rp = build_repo_obj
    rp.open(@sourceDir2, @key)
    rp.perform_decrypt()
    rp.close
  end

  def test_singular_incorrect_password
    create_source_tree2

    # Create in-place repository
    create_source_tree2
    rp = build_repo_obj
    rp.create(@sourceDir2,@key,nil)
    rp.close

    # Update the repo
    cmd = "encr -w #{@sourceDir}  -k #{@key}extrachars"
    outp,success = scall(cmd,false)
    assert_equal(success,false)
    assert(outp.length < 100,"keep these messages small")
  end

  def test_singular_repo_script
    create_source_tree2
    cmd = "encr --init -w #{@sourceDir2}  -k #{@key}"
    scall(cmd)
  end

  def test_singular_encrypt_then_decrypt_script
    create_source_tree2
    cmd = "encr --init -w #{@sourceDir2}  -k #{@key}"
    scall(cmd)
    scall("encr -w #{@sourceDir2} -k #{@key}")
    scall("encr -w #{@sourceDir2} -k #{@key} --decrypt")
  end

  def test_singular_incorrect_password_script
    create_source_tree2
    cmd = "encr --init -w #{@sourceDir2}  -k #{@key}"
    scall(cmd)
    outp,success = scall("encr -w #{@sourceDir2} -k #{@key}wrong",false)
    assert_equal(success,false)
    assert_equal(outp.chomp,"incorrect password")
  end

  def test_encrypt_preserve_filenames
    scall("lencrypt -q -w #{@sourceDir} --key #{@key} --init #{@encryptDir} --orignames")
    scall("lencrypt -q -w #{@sourceDir} --key #{@key}")
    assert(File.file?(File.join(@encryptDir,"ares")))
  end

  def test_singular_encrypt_preserve_filenames
    create_source_tree2
    scall("encr --init -q -w #{@sourceDir2}  -k #{@key} --orignames")
    scall("encr -q -w #{@sourceDir2} -k #{@key}")
    assert(File.file?(File.join(@sourceDir2,"ares")))
  end

end
