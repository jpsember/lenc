require_relative 'repo'

# The application script (i.e., the 'main program')
#
class LEncApp
  include LEnc
  
  def run(argv = ARGV) 
     
    req 'trollop'
    p = Trollop::Parser.new do
        opt :init, "create new encryption repository: KEY ENCDIR ", :type => :strings
        opt :orignames, "(with --init) leave filenames unencrypted"
        opt :storekey, "(with --init) store the key within the repository configuration file so it" \
              " need not be entered with every update"
        opt :update, "update encrypted repository (default operation): KEY", :default => ""
        #opt :updatepwd, "specify key for update: KEY", :type => :string
        opt :recover, "recover files from an encrypted repository: KEY ENCDIR RECDIR", :type => :strings
        opt :where, "specify source directory (default = current directory)", :type => :string
        opt :verbose,"verbose operation"
        opt :quiet, "quiet operation"
        opt :dryrun, "show which files will be modified, but make no changes"
    end
    
    options = Trollop::with_standard_exception_handling p do
      p.parse argv
    end
    
    # Not sure how to determine if there were leftover arguments;
    # trollop seems to include path information ('.')
    #p.die("Unrecognized argument: #{p.leftovers[0]}",nil) if p.leftovers.size
    
    v = 0
    v = -1 if options[:quiet]
    v = 1  if options[:verbose]
    
    update_pwd = options[:update]
    update_pwd = nil if update_pwd.size == 0
    
    nOpt = 0
    nOpt += 1 if options[:init]
    nOpt += 1 if update_pwd  
    nOpt += 1 if options[:recover]
            
    #pr("trollop opts = %s\n",d2(options))
      
    p.die("Only one operation can be performed at a time.",nil) if nOpt > 1
  
    r = Repo.new(:dryrun => options[:dryrun],
      :verbosity => v)
    
    begin

      if (a = options[:init])
        p.die("Expecting: KEY ENCDIR",nil) if a.size != 2
        pwd,encDir = a
        r.create(options[:where], pwd, encDir, options[:orignames], options[:storekey])
      elsif (a = options[:recover])
        p.Trollop::die("Expecting: KEY ENCDIR RECDIR",nil) if a.size != 3
        r.perform_recovery(a[0],a[1],a[2])
      else
        r.open(options[:where],update_pwd)
        r.perform_update(options[:verifyenc])
      end

      r.close()
    rescue Exception =>e
      puts("\nProblem encountered: #{e.message}")
    end

  end
end

if __FILE__ == $0
  args = ARGV
  
  
  LEncApp.new().run(args)
end
  
