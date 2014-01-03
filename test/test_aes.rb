#!/usr/bin/env ruby

require 'js_base/test'
require 'lenc'

class TestAES < Test::Unit::TestCase


def test_050_AES_encryption

    key = "onefishtwofishredfishbluefish"

    f = RepoInternal::MyAES.new(true, key, "42")

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

    f = RepoInternal::MyAES.new(false, key)
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

end
