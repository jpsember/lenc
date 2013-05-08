require_relative 'repo'

class EncrApp
  include LEnc
  
  def run(argv = ARGV) 
     
    req 'trollop'
    p = Trollop::Parser.new do
        opt :init, "create new singular repository"  
        opt :orignames, "(with --init) leave filenames unencrypted"
        opt :encrypt, "encrypt files (default operation)"
        opt :decrypt, "decrypt files"
        opt :key, "encryption key", :type => :string  
        opt :verbose,"verbose operation"
        opt :where, "specify source directory (default = current directory)", :type => :strings
        opt :quiet, "quiet operation"
    end
    
    options = Trollop::with_standard_exception_handling p do
      p.parse argv
    end
    
    v = 0
    v = -1 if options[:quiet]
    v = 1  if options[:verbose]
    
    nOpt = 0
    nOpt += 1 if options[:init]
    nOpt += 1 if options[:encrypt]
    nOpt += 1 if options[:decrypt]
            
    p.die("Only one operation can be performed at a time.",nil) if nOpt > 1
  
    r = Repo.new(:dryrun => options[:dryrun], :verbosity => v)
    
    key = options[:key]
      
    begin
      
      if options[:init]
        r.create(options[:where], key, nil, options[:orignames])
      elsif options[:decrypt]
        r.open(options[:where],key)
        r.perform_decrypt
      else
        r.open(options[:where],key)
        r.perform_encrypt
      end

      r.close()
    rescue Exception =>e
      puts("\nProblem encountered: #{e.message}")
    end

  end
end

if __FILE__ == $0
  args = ARGV
  
  EncrApp.new().run(args)
end
  
