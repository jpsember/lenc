req 'repo'

class LEncApp
  include LEnc

  def run(argv = ARGV)

    p = Trollop::Parser.new do
        opt :init, "create new encryption repository: ENCDIR ", :type => :string
        opt :key, "encryption key", :type => :string
        opt :orignames, "(with --init) leave filenames unencrypted"
        opt :update, "update encrypted repository (default operation)"
        opt :recover, "recover files from an encrypted repository: ENCDIR RECDIR", :type => :strings
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

    nOpt = 0
    nOpt += 1 if options[:init]
    nOpt += 1 if options[:update]
    nOpt += 1 if options[:recover]

    #pr("trollop opts = %s\n",d2(options))

    p.die("only one operation can be performed at a time",nil) if nOpt > 1

    r = Repo.new(:dryrun => options[:dryrun],
      :verbosity => v)

    begin

      if (a = options[:init])
        encDir = a
        r.create(options[:where], options[:key], encDir, options[:orignames])
      elsif (a = options[:recover])
        p.die("expecting ENCDIR RECDIR",nil) if a.size != 2
        r.perform_recovery(options[:key],a[0],a[1])
      else
        r.open(options[:where],options[:key])
        r.perform_encrypt()
      end

      r.close()
    rescue Exception =>e
      die(e.message)
    end
  end
end

if __FILE__ == $0
  args = ARGV

  LEncApp.new().run(args)
end

