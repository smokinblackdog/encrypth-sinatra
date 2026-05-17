require 'bundler/setup'

require 'sinatra'
require 'sinatra/json'
require 'tempfile'
require 'fileutils'
require 'securerandom'
require 'base64'
require 'zip'
require 'marcel'
require 'rack/attack'
require 'rack/timeout/base'
require 'rack/cors'

# моя прелесть
require 'encrypth'
require 'encrypth/web_archiver'

class FileCleanup
  def initialize(file_path, temp_dir = nil)
    @file_path = file_path
    @temp_dir = temp_dir
    @closed = false
  end

  def each
    File.open(@file_path, 'rb') do |file|
      while chunk = file.read(16384)
        yield chunk
      end
    end
  end

  def close
    return if @closed
    @closed = true
    
    begin
      File.delete(@file_path) if @file_path && File.exist?(@file_path)
    rescue => e
      # Игнорируем ошибки удаления
    end
    
    begin
      FileUtils.rm_rf(@temp_dir) if @temp_dir && Dir.exist?(@temp_dir)
    rescue => e
      # Игнорируем ошибки удаления
    end
  end
end

# Rate Limiter для Rack::Attack
class InMemoryRateLimitStore
  def initialize
    @data = {}
    @lock = Mutex.new
  end

  def increment(key, amount = 1, expires_in: nil)
    now = Time.now.to_f
    @lock.synchronize do
      purge_expired!(now)
      entry = @data[key] ||= { value: 0, expires_at: expires_in ? now + expires_in : nil }
      entry[:value] += amount
    end
  end

  def read(key)
    now = Time.now.to_f
    @lock.synchronize do
      purge_expired!(now)
      @data[key]&.fetch(:value, nil)
    end
  end

  def write(key, value, expires_in: nil)
    now = Time.now.to_f
    @lock.synchronize do
      purge_expired!(now)
      @data[key] = { value: value, expires_at: expires_in ? now + expires_in : nil }
      true
    end
  end

  def delete_matched(pattern)
    @lock.synchronize do
      @data.delete_if { |key, _| key.to_s.match?(pattern) }
      true
    end
  end

  private

  def purge_expired!(now)
    @data.delete_if { |_, entry| entry[:expires_at] && entry[:expires_at] <= now }
  end
end

# ============================ НАСТРОЙКИ 
configure do
  set :max_payload_size, 100_000_000 # 100 MB
  set :show_exceptions, false
  set :raise_errors, false
  set :logging, true
end

# ============================ RACK MIDDLEWARE
use Rack::Cors do |cors|
  cors.allow do |allow|
    configured_origins = ENV.fetch('CORS_ALLOWED_ORIGINS', '')
      .split(',')
      .map(&:strip)
      .reject(&:empty?)

    allow.origins(
      *configured_origins,
      %r{\Ahttps?://localhost(?::\d+)?\z},
      %r{\Ahttps?://127\.0\.0\.1(?::\d+)?\z}
    )
    allow.resource '/upload',
      methods: [:post, :options],
      headers: :any,
      credentials: false
    allow.resource '/decrypt',
      methods: [:post, :options],
      headers: :any,
      credentials: false
    allow.resource '/health',
      methods: [:get],
      headers: :any,
      credentials: false
  end
end

use Rack::Attack
use Rack::Timeout, service_timeout: 120
use Rack::Protection, except: :http_origin
use Rack::TempfileReaper

Rack::Attack.cache.store = InMemoryRateLimitStore.new
Rack::Attack.throttle('uploads/ip', limit: 20, period: 60) do |req|
  req.ip if req.path == '/upload' && req.post?
end

# ============================ КОНСТАНТЫ
ALLOWED_EXTENSIONS = %w[
  jpg jpeg png gif bmp webp
  pdf docx xlsx pptx
  txt csv json xml md log
  mp3 mp4 wav ogg flac
  zip 
].freeze

MAX_FILES = 20
MAX_UNPACKED_SIZE = 100_000_000

# ============================ ХЕЛПЕРЫ
helpers do
  def safe_filename?(filename)
    return false if filename.nil? || filename.include?('/') || filename.include?('\\')
    
    # Поддержка .tar.gz
    if filename.end_with?('.tar.gz')
      return true
    end
    
    ext = filename.split('.').last&.downcase
    ALLOWED_EXTENSIONS.include?(ext)
  end

  def validate_file_content!(file_path, filename)
    unless safe_filename?(filename)
      halt 400, json(error: "Forbidden file extension: #{File.extname(filename)}")
    end

    mime = Marcel::MimeType.for(Pathname.new(file_path))
    forbidden_mimes = %w[image/svg+xml text/html application/javascript application/x-msdownload]
    if forbidden_mimes.include?(mime)
      halt 400, json(error: "Forbidden content type in file: #{filename}")
    end

    if filename.end_with?('.zip')
      validate_zip!(file_path)
    end
  end

  def validate_zip!(zip_path)
    total_size = 0
    Zip::File.open(zip_path) do |zip|
      zip.each do |entry|
        total_size += entry.size
        halt 400, json(error: "Zip bomb detected") if total_size > MAX_UNPACKED_SIZE
        halt 400, json(error: "Zip Slip detected") if entry.name.include?('..')
        
        ext = entry.name.split('.').last&.downcase
        unless ALLOWED_EXTENSIONS.include?(ext)
          halt 400, json(error: "Forbidden file inside zip: #{entry.name}")
        end
      end
    end
  rescue Zip::Error
    halt 400, json(error: "Invalid zip archive")
  end

  def safe_temp_path(prefix, ext)
    File.join(Dir.tmpdir, "#{prefix}_#{SecureRandom.hex(8)}#{ext}")
  end
end

# ============================ ЭНДПОИНТЫ

post '/upload' do
  content_type :json
  
  files = params[:files]
  halt 400, json(error: 'No files provided') unless files
  
  files = [files] unless files.is_a?(Array)
  halt 400, json(error: "Too many files, max #{MAX_FILES}") if files.size > MAX_FILES
  
  password = params[:password]
  halt 400, json(error: 'Password required (minimum 8 characters)') if password.nil? || password.length < 8

  temp_dir = Dir.mktmpdir("encrypth_up_")
  encrypted_path = nil
  
  begin
    file_paths = []
    
    files.each do |file|
      validate_file_content!(file[:tempfile].path, file[:filename])
      
      safe_name = file[:filename].gsub(/[^a-zA-Z0-9._-]/, '_')
      dest = File.join(temp_dir, safe_name)
      FileUtils.cp(file[:tempfile].path, dest)
      file_paths << dest
    end

    archiver = Encrypth::WebArchiver.new(password)
    result = archiver.encrypt(file_paths)
    encrypted_path = result[:path]
    
    filename = "secure_#{Time.now.to_i}.tar.enc"
    
    headers(
      'Content-Type' => 'application/octet-stream',
      'Content-Disposition' => "attachment; filename=\"#{filename}\"",
      'Cache-Control' => 'no-cache, no-store'
    )

    FileCleanup.new(encrypted_path, temp_dir)
    
  rescue => e
    logger.error "Upload error: #{e.class} - #{e.message}"
    logger.error e.backtrace.first(5).join("\n")
    
    FileUtils.rm_rf(temp_dir) if temp_dir && Dir.exist?(temp_dir)
    File.delete(encrypted_path) if encrypted_path && File.exist?(encrypted_path)
    
    halt 500, json(error: "Encryption failed")
  end
end

post '/decrypt' do
  content_type :json
  
  file = params[:file]
  halt 400, json(error: 'No file provided') unless file
  
  password = params[:password]
  halt 400, json(error: 'Password required (minimum 8 characters)') if password.nil? || password.length < 8
  
  unless file[:filename].end_with?('.tar.enc')
    halt 400, json(error: 'Invalid file format. Expected .tar.enc')
  end

  temp_extract_dir = Dir.mktmpdir("encrypth_dec_")
  output_zip_path = safe_temp_path("decrypted", ".zip")
  
  begin
    archiver = Encrypth::WebArchiver.new(password)
    archiver.decrypt(file[:tempfile].path, temp_extract_dir)

    extracted_files = Dir.glob(File.join(temp_extract_dir, '**', '*')).reject { |f| File.directory?(f) }
    
    if extracted_files.empty?
      FileUtils.rm_rf(temp_extract_dir)
      halt 400, json(error: 'Archive is empty or wrong password')
    end

    extracted_files.each do |f_path|
      filename = File.basename(f_path)
      ext = filename.split('.').last&.downcase
      unless ALLOWED_EXTENSIONS.include?(ext)
        FileUtils.rm_rf(temp_extract_dir)
        halt 400, json(error: "Forbidden file type inside archive: #{ext}")
      end
    end

    Zip::File.open(output_zip_path, create: true) do |zip|
      extracted_files.each do |f_path|
        relative_path = f_path.sub("#{temp_extract_dir}/", '')
        zip.add(relative_path, f_path)
      end
    end

    headers(
      'Content-Type' => 'application/zip',
      'Content-Disposition' => "attachment; filename=\"decrypted_#{Time.now.to_i}.zip\"",
      'Cache-Control' => 'no-cache, no-store'
    )

    FileCleanup.new(output_zip_path, temp_extract_dir)

  rescue OpenSSL::Cipher::CipherError => e
    logger.error "Auth/Password error: #{e.message}"
    FileUtils.rm_rf(temp_extract_dir) if Dir.exist?(temp_extract_dir)
    File.delete(output_zip_path) if File.exist?(output_zip_path)
    halt 401, json(error: "Invalid password or corrupted file")

  rescue => e
    logger.error "DECRYPTION FAIL"
    logger.error "Class: #{e.class}"
    logger.error "Message: #{e.message.inspect}"
    logger.error e.backtrace.first(10).join("\n")
    
    FileUtils.rm_rf(temp_extract_dir) if Dir.exist?(temp_extract_dir)
    File.delete(output_zip_path) if File.exist?(output_zip_path)
    
    halt 500, json(error: "Decryption failed: #{e.message.empty? ? 'Unknown error' : e.message}")
  end
end

get '/health' do
  content_type :json
  json status: 'ok', time: Time.now.to_i
end

# ============================ ОБРАБОТКА ОШИБОК
error 404 do
  content_type :json
  json error: 'Not found'
end

error do
  content_type :json
  logger.error "Global error: #{env['sinatra.error']&.message}"
  json error: 'Internal server error'
end

# ============================ ЗАПУСК
if __FILE__ == $0
  puts "Encrypth Secure Upload Service running on http://localhost:4567"
end