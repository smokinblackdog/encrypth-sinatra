require 'spec_helper'
require 'json'
require 'zip'

RSpec.describe 'Encrypth Service Integration Test' do
  let(:password) { "full-coverage-test-12345" }

  EXTENSIONS_TO_TEST = %w[
    jpg jpeg png gif bmp webp
    pdf docx xlsx pptx
    txt csv json xml md log
    mp3 mp4 wav ogg flac
    zip
  ]

  let(:format_headers) {
    {
      'png'  => "\x89PNG\r\n\x1A\n".b,
      'jpg'  => "\xFF\xD8\xFF".b,
      'jpeg' => "\xFF\xD8\xFF".b,
      'gif'  => "GIF89a".b,
      'bmp'  => "BM".b,
      'webp' => "RIFF....WEBP".b,
      'pdf'  => "%PDF-1.4".b,
      'mp3'  => "\x49\x44\x33".b,
      'wav'  => "RIFF....WAVE".b,
      'flac' => "fLaC\x00\x00\x00\x22".b,
      'ogg'  => "OggS".b,
      'mp4'  => "\x00\x00\x00\x18ftypisom".b,
      'docx' => "\x50\x4B\x03\x04".b,
      'xlsx' => "\x50\x4B\x03\x04".b,
      'pptx' => "\x50\x4B\x03\x04".b,
      'zip'  => "\x50\x4B\x03\x04".b
    }
  }

  describe 'Health Check' do
    it "returns status ok" do
      get '/health'
      expect(last_response.status).to eq(200)
    end
  end

  describe 'Full Encryption/Decryption Cycle for ALL formats' do
    EXTENSIONS_TO_TEST.each do |ext|
      it "successfully processes .#{ext} files" do
        file = Tempfile.new(["test_file", ".#{ext}"])
        file.binmode
        file_path = file.path

        if %w[zip docx xlsx pptx].include?(ext)
          file.close
          Zip::File.open(file_path, create: true) do |z|
            z.get_output_stream("test.txt") { |f| f.write "data" }
          end
        else
          header = format_headers[ext] || "Test content for #{ext}"
          file.write(header)
          file.close
        end

        # --- UPLOAD ---
        post '/upload', {
          password: password,
          files: Rack::Test::UploadedFile.new(file_path, "application/octet-stream", true, original_filename: "sample.#{ext}")
        }

        expect(last_response.status).to eq(200), "Upload failed for .#{ext}: #{last_response.body}"

        # --- DECRYPT ---
        encrypted_binary = last_response.body
        enc_file = Tempfile.new(['encrypted', '.tar.enc'])
        enc_file.binmode
        enc_file.write(encrypted_binary)
        enc_file_path = enc_file.path
        enc_file.close

        post '/decrypt', {
          password: password,
          file: Rack::Test::UploadedFile.new(enc_file_path, "application/octet-stream", true, original_filename: "archive.tar.enc")
        }

        expect(last_response.status).to eq(200), "Decrypt failed for .#{ext}: #{last_response.body}"

        zip_temp = Tempfile.new(['result', '.zip'])
        zip_temp.binmode
        zip_temp.write(last_response.body)
        zip_temp_path = zip_temp.path
        zip_temp.close

        Zip::File.open(zip_temp_path) do |zip|
          found = zip.entries.any? { |e| e.name.downcase.include?(ext) }
          expect(found).to be true
        end

        [file_path, enc_file_path, zip_temp_path].each { |p| File.delete(p) if File.exist?(p) }
      end
    end
  end

  describe 'Security' do
    it "blocks forbidden content even with allowed extension" do
      bad_file = Tempfile.new(["virus", ".txt"])
      bad_file.write("<!DOCTYPE html><html><body><script>alert(i use arch btw)</script></body></html>")
      bad_file_path = bad_file.path
      bad_file.close

      post '/upload', {
        password: password,
        files: Rack::Test::UploadedFile.new(bad_file_path, "text/plain", true, original_filename: "test.txt")
      }

      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)['error']).to include("Forbidden content type")

      File.delete(bad_file_path) if File.exist?(bad_file_path)
    end
  end
end