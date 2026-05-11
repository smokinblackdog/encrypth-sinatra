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

# моя прелесть
require 'encrypth'

# ============================ НАСТРОЙКИ 
set :max_payload_size, 100_000_000 # 100 MB
set :show_exceptions, false
set :raise_errors, false

# ============================ RACK MIDDLEWARE
use Rack::Attack
use Rack::Timeout, service_timeout: 120
use Rack::Protection
use Rack::TempfileReaper

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
  tar.gz
]

MAX_FILES_PER_REQUEST = 20
MAX_TOTAL_UNPACKED_SIZE = 100_000_000

# ============================ ХЕЛПЕРЫ
helpers do
  def safe_filename?(filename)
    ext = File.extname(filename).downcase[1..-1]
    return false if ext.nil? || ext.empty?
    return false if filename.count('.') > 1 && !filename.end_with?('.tar.gz')
    ALLOWED_EXTENSIONS.include?(ext)
  end
  
  def detect_real_mime_type(file_path)
    Marcel::MimeType.for Pathname.new(file_path)
  rescue
    'application/octet-stream'
  end
  
  def forbidden_by_magic?(file_path)
    mime = detect_real_mime_type(file_path)
    %w[image/svg+xml text/html application/javascript application/x-msdownload].include?(mime)
  end
  
  def safe_zip?(zip_path)
    total_unpacked = 0
    Zip::File.open(zip_path) do |zip|
      zip.each do |entry|
        total_unpacked += entry.size
        return false if total_unpacked > MAX_TOTAL_UNPACKED_SIZE
        return false if entry.symlink?
        return false if entry.name.include?('..') || entry.name.start_with?('/')
        
        ext = File.extname(entry.name).downcase[1..-1]
        return false if !ALLOWED_EXTENSIONS.include?(ext)
      end
    end
    true
  rescue
    false
  end
  
  def validate_file!(file, index)
    filename = file[:filename]
    tempfile = file[:tempfile]
    
    unless safe_filename?(filename)
      halt 400, json(error: "File #{index + 1}: '#{filename}' has unsupported extension")
    end
    
    if forbidden_by_magic?(tempfile.path)
      halt 400, json(error: "File #{index + 1}: '#{filename}' has forbidden content type (SVG/HTML/EXE)")
    end
    
    if filename.end_with?('.zip')
      unless safe_zip?(tempfile.path)
        halt 400, json(error: "File #{index + 1}: '#{filename}' is malformed or contains forbidden content")
      end
    end
    
    true
  end
end

# ============================ ОСНОВНОЙ ЭНДПОИНТ (ШИФРОВАНИЕ)
post '/upload' do
  content_type :json
  
  files = params[:files]
  halt 400, json(error: 'No files provided') unless files
  
  files = [files] unless files.is_a?(Array)
  
  if files.size > MAX_FILES_PER_REQUEST
    halt 400, json(error: "Too many files, max #{MAX_FILES_PER_REQUEST}")
  end
  
  password = params[:password]
  if password.nil? || password.length < 8
    halt 400, json(error: 'Password required (minimum 8 characters)')
  end
  
  # валидация всех файлов
  files.each_with_index do |file, idx|
    validate_file!(file, idx)
  end
  
  # сохраняем файлы во временную папку
  temp_dir = Dir.mktmpdir
  file_paths = []
  
  begin
    files.each do |file|
      dest = File.join(temp_dir, file[:filename].gsub(/[^a-zA-Z0-9._-]/, '_'))
      FileUtils.cp(file[:tempfile].path, dest)
      file_paths << dest
    end
  
    archiver = Encrypth::WebArchiver.new(password)
    result = archiver.encrypt(file_paths)
    
    # отдаём файл
    content_type 'application/octet-stream'
    headers(
      'Content-Disposition' => "attachment; filename=\"secure_#{Time.now.to_i}.tar.enc\"",
      'Content-Length' => result[:size].to_s,
      'Cache-Control' => 'no-cache, no-store'
    )
    
    send_file result[:path], disposition: 'attachment'
    
  ensure
    FileUtils.rm_rf(temp_dir) if temp_dir && Dir.exist?(temp_dir)
  end
end

# ============================ РАСШИФРОВКА
post '/decrypt' do
  content_type :json
  
  encrypted_file = params[:file]
  halt 400, json(error: 'No file provided') unless encrypted_file
  
  password = params[:password]
  if password.nil? || password.length < 8
    halt 400, json(error: 'Password required (minimum 8 characters)')
  end
  
  # проверяем расширение файла
  unless encrypted_file[:filename].end_with?('.tar.enc')
    halt 400, json(error: 'Invalid file format. Expected .tar.enc')
  end
  
  temp_decrypt_dir = nil
  tar_temp = nil
  
  begin
    # создаём временную директорию для расшифрованных файлов
    temp_decrypt_dir = Dir.mktmpdir
    
    archiver = Encrypth::WebArchiver.new(password)
    tar_temp = Tempfile.new(['decrypted', '.tar'])
    tar_temp.binmode
    tar_temp.close
    
    archiver.decrypt(encrypted_file[:tempfile].path, temp_decrypt_dir)
    
    extracted_files = Dir.glob(File.join(temp_decrypt_dir, '**', '*')).reject { |f| File.directory?(f) }
    
    if extracted_files.empty?
      halt 400, json(error: 'No files found in archive or decryption failed')
    end
    
    zip_temp = Tempfile.new(['decrypted_files', '.zip'])
    zip_temp.binmode
    
    Zip::File.open(zip_temp.path, Zip::File::CREATE) do |zip|
      extracted_files.each do |file|
        relative_path = file.sub("#{temp_decrypt_dir}/", '')
        zip.add(relative_path, file)
      end
    end
    
    content_type 'application/zip'
    headers(
      'Content-Disposition' => "attachment; filename=\"decrypted_#{Time.now.to_i}.zip\"",
      'Content-Length' => File.size(zip_temp.path).to_s,
      'Cache-Control' => 'no-cache, no-store'
    )
    
    send_file zip_temp.path, disposition: 'attachment'
  rescue => e
    puts "Decryption error: #{e.message}"
    puts e.backtrace
    halt 500, json(error: "Decryption failed: #{e.message}")
  ensure
    FileUtils.rm_rf(temp_decrypt_dir) if temp_decrypt_dir && Dir.exist?(temp_decrypt_dir)
    tar_temp.unlink if tar_temp && File.exist?(tar_temp.path)
  end
end

# ============================ ЗДОРОВЬЕ
get '/health' do
  content_type :json
  { status: 'ok' }.to_json
end

# ============================ ЗАПУСК
if __FILE__ == $0
  puts "Encrypth Secure Upload Service running on http://localhost:9292"
end