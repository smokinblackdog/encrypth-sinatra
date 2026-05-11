require 'bundler/setup'
require './app'

# Лимит размера запроса
use Rack::ContentLength
use Rack::TempfileReaper

run Sinatra::Application