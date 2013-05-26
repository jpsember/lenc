require 'rake'

Gem::Specification.new do |s|
  s.name        = 'lenc'
  s.version     = '1.2.1'
  s.date        = Time.now
  s.summary     = 'Maintains an encrypted repository of a set of files for secure cloud storage.'

  s.description = <<"DESC"
Encrypts a set of local files, and copies the encrypted versions to a repository, 
which may be located within a free cloud service (Dropbox, Google Drive, Microsoft SkyDrive). 
The program uses the trusted AES 256-bit encryption standard. 
All files are encrypted on the user machine; 
passwords and unencrypted files are never seen by the cloud service. 

It can also encrypt or decrypt directory trees 'in place', so that the original files are
overwritten by their encrypted versions.

DESC


  s.authors     = ["Jeff Sember"]
  s.email       = "jpsember@gmail.com"
  s.homepage    = 'http://www.cs.ubc.ca/~jpsember/'
  fl = FileList['lib/**/*.rb',
                      'bin/*',
                      '[A-Z]*',
                       'test/**/*']
 	fl.exclude(/^test\/workdir/)
  fl.exclude(/^test\/__temp_dirs__/)
  
  s.files = fl.to_a
  
  # We now require the highline gem for entering passwords at console without echoing
  s.add_dependency('highline')

  s.bindir = 'bin'
  s.executables   = FileList['bin/*'].map{|x| File.basename(x)}
  s.test_files = Dir.glob('test/*.rb')
  s.license = 'mit'
end

  
